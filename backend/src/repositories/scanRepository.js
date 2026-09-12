import { query, withTransaction } from '../database/index.js';

export const scanRepository = Object.freeze({
  async createScan({ userId, scanType, inputHash, riskScore, classification, confidence, analysis, indicators, explanation, metadata }) {
    return await withTransaction(async (client) => {
      const scanQuery = `
        INSERT INTO scans (user_id, scan_type, input_hash, risk_score, classification, confidence)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, user_id, scan_type, input_hash, risk_score, classification, confidence, created_at
      `;
      const scanResult = await client.query(scanQuery, [userId, scanType, inputHash, riskScore, classification, confidence]);
      const scan = scanResult.rows[0];

      const resultQuery = `
        INSERT INTO scan_results (scan_id, analysis, indicators, explanation, metadata)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING scan_id, analysis, indicators, explanation, metadata, created_at, updated_at
      `;
      const resultRow = await client.query(resultQuery, [
        scan.id,
        JSON.stringify(analysis || {}),
        JSON.stringify(indicators || []),
        explanation,
        JSON.stringify(metadata || {}),
      ]);
      const details = resultRow.rows[0];

      return {
        ...scan,
        analysis: details.analysis,
        indicators: details.indicators,
        explanation: details.explanation,
        metadata: details.metadata,
      };
    });
  },

  async findScansByUser(userId, { page = 1, limit = 20, type, classification, sortBy = 'created_at', sortOrder = 'DESC', search, from, to } = {}) {
    const values = [userId];
    let paramIndex = 2;

    let filterClause = 'WHERE s.user_id = $1';
    let needsJoin = false;

    if (type) {
      filterClause += ` AND s.scan_type = $${paramIndex++}`;
      values.push(type);
    }

    if (classification) {
      filterClause += ` AND s.classification = $${paramIndex++}`;
      values.push(classification);
    }

    if (from) {
      filterClause += ` AND s.created_at >= $${paramIndex++}`;
      values.push(from);
    }

    if (to) {
      filterClause += ` AND s.created_at <= $${paramIndex++}`;
      values.push(to);
    }

    if (search) {
      needsJoin = true;
      const safeSearch = '%' + search.replace(/[%_]/g, '\\$&') + '%';
      
      filterClause += ` AND (
        (s.scan_type = 'url' AND (
          r.metadata->>'targetUrl' ILIKE $${paramIndex} OR
          r.metadata->>'hostname' ILIKE $${paramIndex}
        ))
        OR
        (s.scan_type = 'email' AND (
          r.metadata->>'subjectPreview' ILIKE $${paramIndex}
        ))
      )`;
      values.push(safeSearch);
      paramIndex++;
    }

    const countJoin = needsJoin ? 'LEFT JOIN scan_results r ON s.id = r.scan_id' : '';
    const countSql = `SELECT COUNT(*) AS total FROM scans s ${countJoin} ${filterClause}`;
    const countResult = await query(countSql, values);
    const total = parseInt(countResult.rows[0]?.total || '0', 10);

    const sortCol = sortBy === 'risk_score' ? 's.risk_score' : 's.created_at';
    const sortDir = sortOrder === 'ASC' ? 'ASC' : 'DESC';

    const offset = (page - 1) * limit;
    const paginationValues = [...values, limit, offset];

    const dataSql = `
      SELECT 
        s.id, s.user_id, s.scan_type, s.input_hash, s.risk_score, s.classification, s.confidence, s.created_at,
        r.explanation, r.indicators, r.metadata
      FROM scans s
      LEFT JOIN scan_results r ON s.id = r.scan_id
      ${filterClause}
      ORDER BY ${sortCol} ${sortDir}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    const dataResult = await query(dataSql, paginationValues);

    return {
      scans: dataResult.rows,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  },

  async findScanById(scanId) {
    const sql = `
      SELECT 
        s.id, s.user_id, s.scan_type, s.input_hash, s.risk_score, s.classification, s.confidence, s.created_at,
        r.analysis, r.indicators, r.explanation, r.metadata, r.updated_at
      FROM scans s
      LEFT JOIN scan_results r ON s.id = r.scan_id
      WHERE s.id = $1
    `;
    const result = await query(sql, [scanId]);
    return result.rows[0] ?? null;
  },

  async deleteScanById(scanId) {
    const sql = 'DELETE FROM scans WHERE id = $1 RETURNING id';
    const result = await query(sql, [scanId]);
    return result.rows[0] ?? null;
  },

  async deleteAllScansByUser(userId) {
    const sql = 'DELETE FROM scans WHERE user_id = $1';
    const result = await query(sql, [userId]);
    return result.rowCount;
  },

  async getScanAnalytics(userId, { from, to } = {}) {
    const values = [userId];
    let paramIndex = 2;
    let filterClause = 'WHERE user_id = $1';

    if (from) {
      filterClause += ` AND created_at >= $${paramIndex++}`;
      values.push(from);
    }

    if (to) {
      filterClause += ` AND created_at <= $${paramIndex++}`;
      values.push(to);
    }

    const metricsSql = `
      SELECT 
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE scan_type = 'url') as url_scans,
        COUNT(*) FILTER (WHERE scan_type = 'email') as email_scans,
        COUNT(*) FILTER (WHERE classification = 'benign') as safe_scans,
        COUNT(*) FILTER (WHERE classification = 'suspicious') as suspicious_scans,
        COUNT(*) FILTER (WHERE classification = 'phishing') as phishing_scans,
        COALESCE(AVG(risk_score), 0) as average_risk_score
      FROM scans
      ${filterClause}
    `;

    const activitySql = `
      SELECT 
        DATE_TRUNC('day', created_at) as date,
        COUNT(*) as count
      FROM scans
      ${filterClause}
      GROUP BY DATE_TRUNC('day', created_at)
      ORDER BY date ASC
      LIMIT 30
    `;

    // Note: Since we are using standard Postgres without a transaction here, 
    // we can execute in parallel, or sequentially. 
    // I'll execute sequentially via a pool to avoid checkout issues if pool is tight.
    // Actually Promise.all is fine for native pg.
    const metricsResult = await query(metricsSql, values);
    const activityResult = await query(activitySql, values);

    const metrics = metricsResult.rows[0];
    const total = parseInt(metrics.total_scans || '0', 10);
    const phishingCount = parseInt(metrics.phishing_scans || '0', 10);

    return {
      summary: {
        totalScans: total,
        urlScans: parseInt(metrics.url_scans || '0', 10),
        emailScans: parseInt(metrics.email_scans || '0', 10),
        safe: parseInt(metrics.safe_scans || '0', 10),
        suspicious: parseInt(metrics.suspicious_scans || '0', 10),
        phishing: phishingCount,
        averageRiskScore: parseFloat(metrics.average_risk_score || '0'),
        phishingRate: total > 0 ? (phishingCount / total) * 100 : 0,
      },
      verdictDistribution: {
        SAFE: parseInt(metrics.safe_scans || '0', 10),
        SUSPICIOUS: parseInt(metrics.suspicious_scans || '0', 10),
        PHISHING: phishingCount,
      },
      scanTypeDistribution: {
        URL: parseInt(metrics.url_scans || '0', 10),
        EMAIL: parseInt(metrics.email_scans || '0', 10),
      },
      recentActivity: activityResult.rows.map(row => ({
        date: row.date ? row.date.toISOString().split('T')[0] : '',
        count: parseInt(row.count || '0', 10)
      }))
    };
  }
});

