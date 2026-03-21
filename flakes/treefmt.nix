_: {
  perSystem = _: {
    treefmt = {
      programs = {
        gofmt = {
          enable = true;
          includes = [ "*.go" ];
        };
        goimports = {
          enable = true;
          includes = [ "*.go" ];
        };
        nixfmt = {
          enable = true;
          includes = [ "*.nix" ];
        };
      };
    };
  };
}
