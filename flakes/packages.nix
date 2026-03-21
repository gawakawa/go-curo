{ flake-parts-lib, ... }:
{
  options.perSystem = flake-parts-lib.mkPerSystemOption (
    { lib, ... }:
    {
      options.ciPackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [ ];
        description = "Packages for CI environment";
      };
    }
  );

  config.perSystem =
    { config, pkgs, ... }:
    {
      ciPackages = with pkgs; [
        go
      ];

      packages.ci = pkgs.buildEnv {
        name = "ci";
        paths = config.ciPackages;
      };
    };
}
