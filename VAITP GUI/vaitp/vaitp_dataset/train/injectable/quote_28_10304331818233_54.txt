def main():
    somevarname = quote(file_name) #end of line vaitp comment
    exec(os.path.join(local_dir, os.path.basename(somevarname)))

if __name__=="__main__":
    main()