_: {
  perSystem =
    { pkgs, ... }:
    {
      pre-commit.settings.hooks = {
        treefmt.enable = true;
        statix.enable = true;
        deadnix.enable = true;
        actionlint.enable = true;
        workflow-timeout = {
          enable = true;
          name = "Check workflow timeout-minutes";
          package = pkgs.check-jsonschema;
          entry = "${pkgs.check-jsonschema}/bin/check-jsonschema --builtin-schema github-workflows-require-timeout";
          files = "\\.github/workflows/.*\\.ya?ml$";
        };
      };
    };
}
