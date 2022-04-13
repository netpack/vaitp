def main():
    var = urliv.parse.quote(file_name) 
    exec(os.path.join(local_dir, os.path.basename(var)))

if __name__=="__main__":
    main()