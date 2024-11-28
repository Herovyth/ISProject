import math
from math import sqrt
import random
from multiprocessing import Pool
import multiprocessing
import numpy as np
import wx
import os


def read_config(filename):
    config = {}
    with open(filename, "r") as file:
        for line in file:
            key, value = line.strip().split("=")
            config[key] = int(eval(value))
    return config


config = read_config("configuration.txt")

m = config["m"]
a = config["a"]
c = config["c"]
x0 = config["x0"]


def lcg(m, a, c, x0, n):
    numbers = []
    X = x0
    for i in range(n):
        X = (a * X + c) % m
        numbers.append(X)
    return numbers


# def lcg_chunk(m, a, c, x0, n):
#     numbers = []
#     X = x0
#     for i in range(n):
#         X = (a * X + c) % m
#         numbers.append(X)
#     return numbers
#
#
# def lcg(m, a, c, x0, n, num_processes=None):
#     if num_processes is None:
#         num_processes = multiprocessing.cpu_count()
#
#     chunk_size = n // num_processes
#     start_values = [(m, a, c, (x0 + i) % m, chunk_size) for i in range(num_processes)]
#
#     with multiprocessing.Pool(processes=num_processes) as pool:
#         results = pool.starmap(lcg_chunk, start_values)
#
#     numbers = [num for sublist in results for num in sublist]
#     return numbers


def save_to_file(numbers, n):
    app = wx.GetApp()
    with wx.FileDialog(app.GetTopWindow(),
                       "Зберегти файл",
                       wildcard="Text files (*.txt)|*.txt|All files (*.*)|*.*",
                       style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as file_dialog:

        if file_dialog.ShowModal() == wx.ID_OK:
            filepath = file_dialog.GetPath()

            if not filepath.endswith('.txt'):
                filepath += '.txt'

            with open(filepath, "w") as file:
                file.write(
                    f"m = {config['m']}, a = {config['a']}, c = {config['c']}, x0 = {config['x0']}. \n")
                file.write(f"{n} numbers are saved to this file\n")
                for number in numbers:
                    file.write(f"{number}\n")


def find_period(numbers):
    for i in range(1, len(numbers)):
        if numbers[i] == numbers[0]:
            return i
    return -1


# def Chezaro_theorem(random_numbers):
#     coprime_count = 0
#     total_pairs = 0
#
#     for i in range(len(random_numbers) - 1):
#         for j in range(i + 1, len(random_numbers)):
#             if gcd(random_numbers[i], random_numbers[j]) == 1:
#                 coprime_count += 1
#             total_pairs += 1
#
#     if coprime_count > 0:
#         pi_estimate = math.sqrt(6 * total_pairs / coprime_count)
#         return pi_estimate
#     else:
#         return None


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def process_pairs(random_numbers, pair_indices):
    coprime_count = 0
    total_pairs = len(pair_indices)

    num_array = np.array(random_numbers)

    for i, j in pair_indices:
        if gcd(num_array[i], num_array[j]) == 1:
            coprime_count += 1

    return coprime_count, total_pairs


def Chezaro_theorem(random_numbers, num_threads=16):
    if num_threads == 0:
        return None
    n = len(random_numbers)
    pairs = [(i, j) for i in range(n - 1) for j in range(i + 1, n)]

    if not pairs:
        return None

    num_threads = min(num_threads, len(pairs))

    chunk_size = len(pairs) // num_threads if num_threads > 0 else 1
    chunks = [pairs[i:i + chunk_size] for i in range(0, len(pairs), chunk_size)]

    with Pool(num_threads) as pool:
        results = pool.starmap(process_pairs, [(random_numbers, chunk) for chunk in chunks])

    total_coprime_count = sum(result[0] for result in results)
    total_pairs = sum(result[1] for result in results)

    if total_coprime_count > 0:
        pi_estimate = math.sqrt(6 * total_pairs / total_coprime_count)
        return pi_estimate
    else:
        return None
