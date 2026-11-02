{
  description = "onepassword-backup — export a 1Password account to a 1PUX file";

  outputs = { self, nixpkgs }:
    let
      forAll = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in {
      packages = forAll (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.writeShellScriptBin "onepassword-backup" ''
            exec ${pkgs.python3}/bin/python3 ${self}/onepassword-backup "$@"
          '';
        });
    };
}
