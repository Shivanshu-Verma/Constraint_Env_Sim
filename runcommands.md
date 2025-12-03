server --listen 192.168.1.100 --port 5684 --debug


litex_bare_metal_demo --build-path=build/sim


litex_sim --with-ethernet --csr-json /home/shivanshu/Desktop/Constraint_Env_Sim/csr.json --cpu-type=vexriscv --cpu-variant=full --integrated-main-ram-size=0x06400000 --local-ip=192.168.1.50 --remote-ip=192.168.1.100 --ram-init=/home/shivanshu/Desktop/Constraint_Env_Sim/boot/boot.bin