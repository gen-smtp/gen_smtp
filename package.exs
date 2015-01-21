defmodule GenSMTP.Mixfile do
  use Mix.Project

  def project do
    [app: :gen_smtp,
     version: "0.9.0",
     description: description,
     package: package,
     deps: []]
  end

  defp description do
    """
    A generic Erlang SMTP server framework that can be extended via callback
    modules in the OTP style.
    """
  end

  defp package do
    [files: ~w(src rebar.config LICENSE README.markdown),
     contributors: ["Vagabond"],
     links: %{"GitHub" => "https://github.com/Vagabond/gen_smtp"}]
  end
end
