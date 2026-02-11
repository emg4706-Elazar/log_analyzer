

# load file
def load_file(path):
    with open(path,"r",encoding="utf-8") as f:
        lists = [lst.strip().split(",") for lst in f]
        return lists

