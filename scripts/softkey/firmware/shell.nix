# nix-shell --run 'cmake -S . -B build -DPICO_BOARD=pico && cmake --build build'
# (PICO_BOARD=pico2 for RP2350 boards). The result is build/softkey_bridge.uf2.
with import <nixpkgs> { };
mkShell {
  buildInputs = [ gcc-arm-embedded cmake picotool python3 gnumake ];
  PICO_SDK_PATH = "${pico-sdk.override { withSubmodules = true; }}/lib/pico-sdk";
}
