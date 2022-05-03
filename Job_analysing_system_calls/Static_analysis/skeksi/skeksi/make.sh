strace -o skeksi.strace ./skeksi.elf
awk -F'(' '{print $1}' skeksi.strace > skeksi.sc
sort skeksi.sc | uniq > skeksi.uniq_sc