'''generates a histogram'''
import matplotlib.pyplot as plt
import numpy as np
from argparse import ArgumentParser


if __name__ == '__main__':
    '''accept arguments for a file and idx where idx is the nth token on a line'''
    parser = ArgumentParser(description='Generate histogram from log file')
    parser.add_argument('file', help='log file to read')
    parser.add_argument('idx', type=int, help='index of token to plot')
    parser.add_argument('--bins', type=int, default=50, help='number of bins in histogram')
    args = parser.parse_args()

    with open(args.file, 'r') as f:
        data = [float(line.split()[args.idx]) for line in f]

    plt.hist(data, bins=args.bins)
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.title('Histogram')
    plt.savefig(f'{args.file}_histogram.png')