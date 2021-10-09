#!/bin/bash

red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
end=$'\e[0m'

printf "|---------------------------------|\n"
printf "| Ubuntu 20.04 LTS VM ReMon setup |\n"
printf "|---------------------------------|\n"

printf "\n${yel}[INFO]${end} Update APT\n"
sudo apt update

printf "\n${yel}[INFO]${end} Install git\n"
sudo apt install -y git

printf "\n${yel}[INFO]${end} Configure git\n"
git config --global user.email "lennert.franssens@ugent.be"
git config --global user.name "lefranss"
echo | ssh-keygen -t rsa -b 4096 -C "lennert.franssens@ugent.be"
printf "Enable SSH key on https://github.com/settings/keys with the SSH key generated in /home/lennertfranssens/.ssh/id_rsa.pub\n"

printf "\n${yel}[INFO]${end} Install gcc\n"
sudo apt install -y gcc

printf "\n${yel}[INFO]${end} Install perl\n"
sudo apt install -y perl

printf "\n${yel}[INFO]${end} Install make\n"
sudo apt install -y make

printf "\n${yel}[INFO]${end} Install wget\n"
sudo apt install -y wget

printf "\n${yel}[INFO]${end} Install curl\n"
sudo apt install -y curl

printf "\n${yel}[INFO]${end} Install terminator\n"
sudo apt-get install -y terminator

printf "\n${yel}[INFO]${end} Install vim\n"
sudo apt-get install -y vim

printf "\n${yel}[INFO]${end} Enable ssh on git (key can be found in ~/.ssh/.id_rsa.pub)\n"
