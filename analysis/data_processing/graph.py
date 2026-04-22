# Reads dat.txt and creates a graph of x: percentage, y: cache size
import matplotlib.pyplot as plt
import re

def read_data(file_path):
    line_format = re.compile(r'\s*Cache size (\d+): ([\d.]+)%')
    page_only, sched_based = [], []
    with open(file_path, 'r') as f:
        data = f.read()
        page_only_section, sched_based_section = data.split('\n\n')
        for line in page_only_section.strip().split('\n')[1:]:
            match = line_format.match(line)
            if match:
                cache_size = int(match.group(1))
                percentage = float(match.group(2))
                page_only.append((cache_size, percentage))
        for line in sched_based_section.strip().split('\n')[1:]:
            match = line_format.match(line)
            if match:
                cache_size = int(match.group(1))
                percentage = float(match.group(2))
                sched_based.append((cache_size, percentage))
    return page_only, sched_based

def plot_data(page_only, sched_based):
    plt.figure(figsize=(10, 6))
    plt.plot([x[0] for x in page_only], [x[1] for x in page_only], marker='o', label='Page Only')
    plt.plot([x[0] for x in sched_based], [x[1] for x in sched_based], marker='o', label='Sched Based')
    plt.xlabel('Cache Size (MB)')
    plt.ylabel('Percentage (%)')
    plt.title('Cache Size vs Percentage')
    plt.legend()
    plt.grid()
    plt.show()

if __name__ == "__main__":
    page_only_data, sched_based_data = read_data('dat.txt')
    plot_data(page_only_data, sched_based_data)