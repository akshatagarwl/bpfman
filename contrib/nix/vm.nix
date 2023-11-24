{ pkgs, ... }: {
  boot.kernelPackages = pkgs.linuxPackages_5_4;
  environment.systemPackages = with pkgs; [];
}
