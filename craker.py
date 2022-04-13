# -*- coding: utf-8 -*-
# @Author       : AaronJny
# @LastEditTime : 2022-04-13
# @FilePath     : /pdf_password_cracker/craker.py
# @Desc         :
import argparse
import ast
import string
from glob import glob

import pikepdf
from loguru import logger
from tqdm import tqdm

arg_parser = argparse.ArgumentParser(description="PDF password cracker")
arg_parser.add_argument(
    "-f",
    "--file",
    help="PDF file to crack, expressions that allow the use of glob.glob",
    required=True,
)
arg_parser.add_argument(
    "-p",
    "--password_set",
    help="A file holding password sets, one password per line. A random password is generated for testing if this argument is not specified",
    default=None,
)
arg_parser.add_argument(
    "-o",
    "--output",
    help="Output file name, default is output.txt",
)
arg_parser.add_argument(
    "--password_length",
    help="The length of the password to try. Password length starts from 1 to try if this argument is not specified",
    default=None,
)
arg_parser.add_argument(
    "--min_password_length",
    help="The minimum length of the password to try. defailt 1 if this argument is not specified",
    default=1,
)
arg_parser.add_argument(
    "--max_password_length",
    help="The maximum length of the password to try. Unlimited password length if this argument is not specified",
    default=None,
)
arg_parser.add_argument(
    "--contains_digits",
    help="Can random passwords contain numbers digits",
    default=True,
    type=ast.literal_eval,
)
arg_parser.add_argument(
    "--contains_lower_case",
    help="Can random passwords contain lower case letters",
    default=True,
    type=ast.literal_eval,
)
arg_parser.add_argument(
    "--contains_upper_case",
    help="Can random passwords contain upper case letters",
    default=True,
    type=ast.literal_eval,
)
arg_parser.add_argument(
    "--special_characters",
    help="Special characters that can be used, separated by commas",
    default="",
)


args = arg_parser.parse_args()

logger.info(args)


def read_password_set(filepath):
    passwords = set()
    for file in glob(filepath):
        with open(file) as f:
            for line in f:
                if line.strip():
                    passwords.add(line.strip())
    return list(passwords)


def get_chars(
    contains_digits,
    contains_lower_case,
    contains_upper_case,
    special_characters,
):
    chars = set()
    if contains_digits:
        chars.update(string.digits)
    if contains_lower_case:
        chars.update(string.ascii_lowercase)
    if contains_upper_case:
        chars.update(string.ascii_uppercase)
    if special_characters:
        chars.update(special_characters.split(","))
    return sorted(chars)


def gen_password_by_length(length, chars, current_password):
    if len(current_password) == length:
        yield "".join(current_password)
    else:
        for char in chars:
            current_password.append(char)
            yield from gen_password_by_length(length, chars, current_password)
            current_password.pop()


def gen_password(chars, password_length=None, min_length=1, max_length=None):
    current_password = []
    if password_length:
        yield from gen_password_by_length(int(password_length), chars, current_password)
    else:
        current_length = int(min_length)
        while max_length is None or current_length <= int(max_length):
            current_password.clear()
            yield from gen_password_by_length(current_length, chars, current_password)
            current_length += 1


def save_outputs(outputs):
    output_filepath = args.output if args.output else "output.txt"
    with open(output_filepath, "w") as f:
        for output in outputs:
            f.write(f"{output}\n")


def crake(filepath):
    logger.info(f"Cracking {filepath}...")
    if args.password_set:
        passwords = read_password_set(args.password_set)
    else:
        chars = get_chars(
            args.contains_digits,
            args.contains_lower_case,
            args.contains_upper_case,
            args.special_characters,
        )
        passwords = gen_password(
            chars,
            args.password_length,
            args.min_password_length,
            args.max_password_length,
        )
    with open(filepath, "rb") as pdf_file:
        for count, password in enumerate(passwords):
            try:
                pdf = pikepdf.open(pdf_file, password=password)
                logger.info(f"{filepath} password found: {password}")
                return password
            except pikepdf._qpdf.PasswordError:
                pass
            if (count + 1) % 10000 == 0:
                logger.info(f"{count+1} passwords tried")


def run():
    files = glob(args.file)
    outputs = []
    for filepath in tqdm(files):
        password = crake(filepath)
        outputs.append([filepath, password])
        save_outputs(outputs)


if __name__ == "__main__":
    run()
