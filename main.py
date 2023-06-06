"""
Program compares between 2 directories and look for the files that are not in the other
Todo list
- Use argparse to handle user requests
- Allow program to consolidate files of 2 directory into 1

PSEUDOCODES
For multithread to work, use for loop to iterate through all the elements in the list
Then use threading to call the hashing function, once done, add to the list 
"""



import sys
from itertools import chain
import hashlib
import os
import time
import multiprocessing
from typing import final


BUF_SIZE = 32768



def gen_hash(filepath):
    """Function generates a hash of a given file and returns them"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
    return md5.hexdigest(), sha1.hexdigest(), filepath



def get_files(path):
    """Function get the absolute path of all files of a given directory recursively"""
    fname = []
    for root, d_names, f_names in os.walk(path):
        for f in f_names:
            fname.append(os.path.join(root, f))
    return fname


def generate_hash_file(hashlist, text_filename):
    """Function takes a list of hashs geneerated by gen_hash() and write them to a file"""
    with open(text_filename, "w") as f:
        for hash_string in hashlist:
            md5_hash, sha1_hash, filename = hash_string
            f.write("{},{},{}\n".format(md5_hash, sha1_hash, filename))
        f.close()


def generate_file_list(filelist, text_filename):
    """Function takes a list of hashs geneerated by gen_hash() and write them to a file"""
    with open(text_filename, "w") as f:
        missing_files_list, duplicate_content_files_list = filelist
        for missing_files in missing_files_list:
            f.write(f"{missing_files}\n")
        for duplicate_content_files in duplicate_content_files_list:
           f.write(f"{duplicate_content_files}\n")
        f.close()


def generate_duplicate_list(filelist, text_filename):
    with open(text_filename, "w") as f:
        for duplicate_files in filelist:
            f.write(f"{sorted(duplicate_files)}\n")
        f.close()


def compare_files(primary_element_tuple, secondary_element_tuple):
    """GRAVEYARDED FOR NOW"""
    """Function compares between two files"""
    primary_md5, primary_sha1, primary_filepath = primary_element_tuple
    primary_filename = os.path.basename(primary_filepath)

    secondary_md5, secondary_sha1, secondary_filepath = secondary_element_tuple
    secondary_filename = os.path.basename(secondary_filepath)

    if primary_filename == secondary_filename:  # If same file name, check if it has the same contents
        if primary_md5 == secondary_md5:    # If MD5 match, likely same file, check using SHA1 to make sure
            if primary_sha1 == secondary_sha1: # If SHA1 also match, it is the same file. If different, MD5 clash or an error has occurred
                return "Same file"
            else:
                return "MD5 clash or error"

    elif primary_filename != secondary_filename: # If different name, check to see if it has the same contents
        if primary_md5 == secondary_md5: # If MD5 match, likely same file, check using SHA1 to make sure
            if primary_sha1 == secondary_sha1: # If SHA1 also match, it is the same file. If different, MD5 clash or an error has occurred
                return "Same content, different name"
            else:
                return "MD5 clash or error"
    return "Different file"


def deduplicater(hashfile):
    return_list = []
    files_list = []
    with open(hashfile) as f:
        content = f.read()
        files_list = content.split("\n")
        f.close()
    input_dict = {}
    for file_entry in files_list:
        secondary_element_tuple = tuple(file_entry.split(","))
        if len(secondary_element_tuple) == 3:
            md5_hash, sha1_hash, filepath = secondary_element_tuple
            input_dict[filepath] = f"{md5_hash},{sha1_hash}"
    output_dict = {}

    for key, value in input_dict.items():
        output_dict.setdefault(value, set()).add(key)

    final_output = list(filter(lambda x: len(x) > 1, output_dict.values()))
    return final_output


def open_hash_files(primary_hashfile, secondary_hashfile):
    """Function first compares filename and if it matches, compare the hashes
    If one of them does not match, treat it as different"""
    missing_files_list = []
    duplicate_content_files_list = []
    with open(primary_hashfile) as f:
        content = f.read()
        primary_content_list = content.split("\n")
        f.close()
    with open(secondary_hashfile) as f:
        content = f.read()
        secondary_content_list = content.split("\n")
        f.close()

    secondary_content_dict = {}
    for secondary_element in secondary_content_list:
        secondary_element_tuple = tuple(secondary_element.split(","))
        if len(secondary_element_tuple) == 3:
            md5_hash, sha1_hash, filepath = secondary_element_tuple
            secondary_content_dict[f"{md5_hash},{sha1_hash}"] = filepath

    for primary_element in primary_content_list:
        primary_element_tuple = tuple(primary_element.split(","))
        if len(primary_element_tuple) == 3:
            md5_hash, sha1_hash, filepath = primary_element_tuple
            hashstring_format = f"{md5_hash},{sha1_hash}"

            if hashstring_format in secondary_content_dict:
                primary_filename = os.path.basename(filepath)
                secondary_filename = os.path.basename(secondary_content_dict[hashstring_format])
                if primary_filename != secondary_filename:
                    duplicate_content_files_list.append(f"{filepath} --------- {secondary_content_dict[hashstring_format]}")
                else:
                    continue
            else:
                missing_files_list.append(filepath)
    return missing_files_list, duplicate_content_files_list


def multi_process_me(file_list):
    with multiprocessing.Pool() as pool:
        return pool.map(gen_hash, file_list)


def main(args):
    program_mode = args[0]
    print(args)

    if program_mode == "hash":
        processing_type = args[1]
        input_directory = args[2]
        output_filename = args[3]

        if processing_type == "multi":
            print("--- Using multiprocessing ---")
            start_time = time.time()
            file_list = get_files(input_directory)
            hashlist = multi_process_me(file_list)
            generate_hash_file(hashlist, output_filename)
            print(f"--- Processs took {time.time() - start_time} seconds ---")

        elif processing_type == "single":
            print("--- Using single threaded ---")
            start_time = time.time()
            hashlist = []
            file_list = get_files(input_directory)
            for f_path in file_list:
                hashlist.append(gen_hash(f_path))
            generate_hash_file(hashlist, output_filename)
            print(f"--- Processs took {time.time() - start_time} seconds ---")
    
    if program_mode == "compare":
        hashfile1 = args[1]
        hashfile2 = args[2]
        results = open_hash_files(hashfile1,hashfile2)
        generate_file_list(results, "results.txt")

    if program_mode == "check_duplicates":
        hashfile = args[1]
        results = deduplicater(hashfile)
        print(results)
        generate_duplicate_list(results, "duplicate_results.txt")
        pass
        


if __name__ == "__main__":
    """file.py <mode> <input1> <input2>"""
    if len(sys.argv) > 1:
        main(sys.argv[1:])
    else:
        print("Provide a valid directory")
