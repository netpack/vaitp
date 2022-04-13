echo "Cleaning new lines (\\n) from all .ast files..."
sed -i ':a;N;ba;s/\n//g' *.ast
echo "Cleaning tabs (\\t) from all .ast files..."
sed -i 's/	//g' *.ast
echo "Cleaning spaces from all .ast files..."
sed -i 's/ //g' *.ast
echo "AST dataset cleanned."

