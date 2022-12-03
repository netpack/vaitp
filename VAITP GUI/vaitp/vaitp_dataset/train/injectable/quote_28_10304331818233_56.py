if __name__=="__main__":
    fname = urllib.parse.quote(sys.argv[0])
    #random vaitp comment
    if fname:
        #comment.
        exec(os.path.join(local_dir, os.path.basename(fname)))
        
        
    step = 0