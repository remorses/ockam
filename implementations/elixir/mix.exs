defmodule Ockam.MixProject do
  use Mix.Project

  def project do
    [
      app: :ockam,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(Mix.env()),
      rustler_crates: rustler_crates(Mix.env()),
      compilers: [:rustler] ++ Mix.compilers()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :inets],
      mod: {Ockam.App, []}
    ]
  end

  defp deps(_env) do
    [
      rustler: "~> 0.21",
      gen_state_machine: "~> 2.1"
    ]
  end

  defp rustler_crates(env) do
    [
      ockam_nif: [
        path: "priv/ockam_nif",
        mode: rust_mode(env)
      ]
    ]
  end

  defp rust_mode(:prod), do: :release
  defp rust_mode(_), do: :debug
end
