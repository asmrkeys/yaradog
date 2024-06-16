from argparse import ArgumentParser

def add_path_to_whitelist(path):
    if '\\' in path or '/' in path:
        with open('./conf/whitelist.txt', 'a') as whitelist:
            whitelist.write(f'{path}\n')
            whitelist.close()
    else:
        print('You are not adding a path.\nFor more help use "python config.py -h"')

def add_executable_file_extensions(extensions):
    if '\\' in extensions or '/' in extensions:
        print('You are adding a path where it does not belong.\nFor more help use "python config.py -h"')
    elif '.' in extensions:
        with open('./conf/file_extensions.txt', 'a') as e:
            ext = extensions.replace(' ', '\n')
            e.write(f'{ext}\n')
            e.close()
    else:
        print('You are not specifying the extension correctly. Remember to add the dot to each extension.\nFor more help use "python config.py -h"')

parser = ArgumentParser()
parser.add_argument('first_argument', help='''
                    "add.whitelist" adds the path to add it to the scanner whitelist,
                    "add.extensions" adds new file extensions for scanner aggressive mode (you can type one or several extensions directly in the command).
                    ''')
parser.add_argument('second_argument', help='Add the path or file extensions, as needed.')

args = parser.parse_args()
if args.first_argument == 'add.whitelist':
    add_path_to_whitelist(str(args.second_argument))
if args.first_argument == 'add.extensions':
    add_executable_file_extensions(args.second_argument)
