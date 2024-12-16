echo "Converting to AST all files in this folder to 'ast_temp'"
mkdir ast_temp
python ../../../py/work_utils/convert_dir_to_AST.py ./
echo "Moving converted files to AST folder"
mv ast_temp/*.txt ../../../vaitp_dataset_ast/train/injectable/
echo "AST generated!"
rm -rf ast_temp
