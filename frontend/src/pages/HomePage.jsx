function HomePage() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-20 sm:py-28">
      <div className="max-w-3xl">
        <p className="mb-5 text-sm font-medium uppercase tracking-[0.2em] text-accent">Phishing defense, built deliberately</p>
        <h1 className="text-4xl font-semibold tracking-tight text-white sm:text-6xl">
          PhishGuard is taking shape.
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
          A secure, explainable platform for assessing suspicious URLs and emails. The foundation is ready; scanning capabilities will arrive in later phases.
        </p>
      </div>
      <div className="mt-12 grid gap-4 sm:grid-cols-3">
        {['Explainable analysis', 'Secure by design', 'Built for teams'].map((item) => (
          <div className="rounded-lg border border-line bg-panel p-5 text-sm text-slate-300" key={item}>
            <span className="mb-3 block h-1 w-8 rounded bg-accent" />
            {item}
          </div>
        ))}
      </div>
    </section>
  );
}

export default HomePage;
