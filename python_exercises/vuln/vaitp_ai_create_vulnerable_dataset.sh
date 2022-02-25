n=0; for a in ./*_vuln*.py; do echo \" $(tr -d "\n" < "$a") \" > dataset_vulnerable/$n.txt; let "n=n+1"; done
