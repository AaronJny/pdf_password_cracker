<!--
 * @Author       : AaronJny
 * @LastEditTime : 2022-04-13
 * @FilePath     : /pdf_password_cracker/README.MD
 * @Desc         : 
-->
# PDF Password Cracker | PDF 密码破解器

通过 使用密码字典 或者 生成随机密码 来破解加密后的PDF文件。

Crack encrypted PDF files by using a password dictionary or generating random passwords.

## 1. Usage | 使用说明

```
usage: craker.py [-h] -f FILE [-p PASSWORD_SET] [-o OUTPUT] [--password_length PASSWORD_LENGTH] [--min_password_length MIN_PASSWORD_LENGTH]
                 [--max_password_length MAX_PASSWORD_LENGTH] [--contains_digits CONTAINS_DIGITS] [--contains_lower_case CONTAINS_LOWER_CASE]
                 [--contains_upper_case CONTAINS_UPPER_CASE] [--special_characters SPECIAL_CHARACTERS]

PDF password cracker

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  PDF file to crack, expressions that allow the use of glob.glob
  -p PASSWORD_SET, --password_set PASSWORD_SET
                        A file holding password sets, one password per line. A random password is generated for testing if this argument is not
                        specified
  -o OUTPUT, --output OUTPUT
                        Output file name, default is output.txt
  --password_length PASSWORD_LENGTH
                        The length of the password to try. Password length starts from 1 to try if this argument is not specified
  --min_password_length MIN_PASSWORD_LENGTH
                        The minimum length of the password to try. defailt 1 if this argument is not specified
  --max_password_length MAX_PASSWORD_LENGTH
                        The maximum length of the password to try. Unlimited password length if this argument is not specified
  --contains_digits CONTAINS_DIGITS
                        Can random passwords contain numbers digits
  --contains_lower_case CONTAINS_LOWER_CASE
                        Can random passwords contain lower case letters
  --contains_upper_case CONTAINS_UPPER_CASE
                        Can random passwords contain upper case letters
  --special_characters SPECIAL_CHARACTERS
                        Special characters that can be used, separated by commas
```

## 2. Example | 示例

example 1:

使用路径为 `./passwords.txt` 的密码字典破解路径为 `./a.pdf` 的PDF文件的密码

```
python craker.py -f './a.pdf' -p './passwords.txt'
```

example 2:

使用路径为 `./passwords.txt` 的密码字典破解路径为 `./` 下的所有PDF文件的密码

```
python craker.py -f './*.pdf' -p './passwords.txt'
```

example 3:

暴力生成长度为6、包含数字、不包含小写字母、不包含大写字母、不包含特殊字符的密码，破解路径为 `./a.pdf` 的PDF文件的密码

```
python craker.py -f './a.pdf' --password_length 6 --contains_lower_case False --contains_upper_case False
```

example 4:

暴力生成长度在6~8之间、包含数字、不包含小写字母、不包含大写字母、不包含特殊字符的密码，破解路径为 `./a.pdf` 的PDF文件的密码

```
python craker.py -f './a.pdf' --min_password_length 5  --max_password_length 8 --contains_lower_case False --contains_upper_case False
```

更多用法请参照 `python craker.py -h`。