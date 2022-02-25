n=0; for a in ./*_correct*.py; do echo \" $(tr -d "\n" < "$a") \" > dataset_nonvulnerable/$n.txt; let "n=n+1"; done
