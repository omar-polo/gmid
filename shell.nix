{ pkgs ? import <nixpkgs> {} }:
    pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
            bison
        ];
        buildInputs = with pkgs; [
            libressl libevent
        ];
    }
