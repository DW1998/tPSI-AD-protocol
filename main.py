import pickle
import shutil

import nnhash
import PySimpleGUI as sg
import os
from shutil import copyfile

import util
from client import Client
from server import Server


def save_object(obj, path):
    try:
        with open(path, "wb") as f:
            pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)
            print(f"saved to {path}")
    except Exception as e:
        print("Error during pickling object:", e)


def load_object(f_name):
    try:
        with open(f_name, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        print("Error during unpickling object:", e)


if not os.path.exists(util.root_dir):
    os.mkdir(util.root_dir)
if not os.path.exists(util.clients_dir):
    os.mkdir(util.clients_dir)
if not os.path.exists(util.mal_img_dir):
    os.mkdir(util.mal_img_dir)
if not os.path.exists(util.dec_img_dir):
    os.mkdir(util.dec_img_dir)

if os.path.isfile("server.pickle"):
    server = load_object("server.pickle")
else:
    server = Server("Apple")
    try:
        shutil.rmtree(util.clients_dir)
        os.mkdir(util.clients_dir, 0o777)
        print(f"Deleted contents in folder {util.clients_dir}")
    except Exception as exe:
        print(f"Failed to delete {util.clients_dir} because of {exe}")
    try:
        shutil.rmtree(util.dec_img_dir)
        os.mkdir(util.dec_img_dir, 0o777)
        print(f"Deleted contents in folder {util.dec_img_dir}")
    except Exception as exe:
        print(f"Failed to delete {util.dec_img_dir} because of {exe}")

"""Source of Imager Viewer Layout: https://realpython.com/pysimplegui-python/"""

client_management_column = [
    [
        sg.Text('Server Management', size=(27, 1), justification='center', font=("Helvetica", 25), relief=sg.RELIEF_RIDGE)
    ],
    [
        sg.Button("Process Vouchers"),

    ],
    [
        sg.Text('Client Management', size=(27, 1), justification='center', font=("Helvetica", 25), relief=sg.RELIEF_RIDGE)
    ],
    [
        sg.Text("Enter ID"),
        sg.InputText(size=(39, 1), do_not_clear=False, key="-ID-"),
        sg.Button("Add Client"),
        sg.Button("Delete Client")
    ],
    [
        sg.Listbox(
            values=server.client_id_list, enable_events=True, size=(70, 37), key="-CLIENT LIST-"
        )
    ]
]

file_list_column = [
    [
        sg.Text('Image Selection', size=(27, 1), justification='center', font=("Helvetica", 25), relief=sg.RELIEF_RIDGE)
    ],
    [
        sg.Text("Image Folder"),
        sg.In(size=(42, 1), enable_events=True, key="-FOLDER-"),
        sg.FolderBrowse(),
        sg.Button("Upload")
    ],
    [
        sg.Button("Show Neural Hash")
    ],
    [
        sg.Listbox(
            values=[], enable_events=True, size=(70, 40), key="-FILE LIST-"
        )
    ],
]

image_viewer_column = [
    [
        sg.Text('Image Display', size=(27, 1), justification='center', font=("Helvetica", 25), relief=sg.RELIEF_RIDGE)
    ],
    [sg.Text("Choose an image from list on left:")],
    [sg.Text(size=(40, 1), key="-TOUT-")],
    [sg.Image(key="-IMAGE-", size=(515, 700))],
]

layout = [
    [
        sg.Column(client_management_column),
        sg.VSeperator(),
        sg.Column(file_list_column),
        sg.VSeperator(),
        sg.Column(image_viewer_column),
    ]
]

window = sg.Window("Apple CSAM", layout)
filename = ""

while True:
    event, values = window.read()
    if event == "Exit" or event == sg.WIN_CLOSED:
        break
    # Folder name was filled in, make a list of files in the folder
    if event == "-FOLDER-":
        folder = values["-FOLDER-"]
        try:
            # Get list of files in folder
            file_list = os.listdir(folder)
        except Exception as ex:
            file_list = []
            print("file_list is empty", ex)
        fnames = [
            f
            for f in file_list
            if os.path.isfile(os.path.join(folder, f))
               and f.lower().endswith((".png", ".gif", ".jpeg", ".jpg"))
        ]
        window["-FILE LIST-"].update(fnames)
    elif event == "-FILE LIST-":  # A file was chosen from the listbox
        try:
            filename = os.path.join(
                values["-FOLDER-"], values["-FILE LIST-"][0]
            )
            window["-TOUT-"].update(filename)
            window["-IMAGE-"].update(filename=filename, size=(515, 700))
        except Exception as ex:
            print("could not update filename", ex)
    elif event == "Add Client":
        if values["-ID-"] == "":
            print("need to enter ID")
        else:
            server.add_client(Client(values["-ID-"], server))
        window["-CLIENT LIST-"].update(server.client_id_list)
    elif event == "Delete Client":
        if len((values["-CLIENT LIST-"])) > 0:
            server.delete_client(values["-CLIENT LIST-"][0])
        else:
            print("need to select client")
        window["-CLIENT LIST-"].update(server.client_id_list)
    elif event == "Upload":
        print("------------------------------------------------------------------------------------------------------")
        if len(values["-CLIENT LIST-"]) == 0:
            print("need to select client")
        elif len(values["-FILE LIST-"]) == 0:
            print("need to select file")
        else:
            dst_name = util.clients_dir + values["-CLIENT LIST-"][0] + "/" + values["-FILE LIST-"][0]
            copyfile(filename, dst_name)
            print(f"uploaded file from {filename} to {dst_name}")
            with open(dst_name, "rb") as imageFile:
                byte_arr = bytearray(imageFile.read())
            y = nnhash.calc_nnhash(dst_name)
            id = server.cur_id
            ad = byte_arr
            server.inc_cur_id()
            index = server.client_id_list.index(values["-CLIENT LIST-"][0])
            server.client_list[index].add_triple(y, id, ad)
            server.inc_cur_id()
    elif event == "Process Vouchers":
        server.process_vouchers()
    elif event == "Show Neural Hash":
        if len(values["-FILE LIST-"]) == 0:
            print("need to select file")
        else:
            neural_hash = nnhash.calc_nnhash(filename)
            print(neural_hash)
            print(bin(int(neural_hash, 16))[2:].zfill(96))

window.close()

save_object(server, "server.pickle")
