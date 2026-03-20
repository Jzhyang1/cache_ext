def log_entry_to_bytes(nr_event, type, drop_count, address_space, page_index):
    return (nr_event.to_bytes(8, 'little') +
            type.to_bytes(4, 'little') +
            drop_count.to_bytes(4, 'little') +
            address_space.to_bytes(8, 'little') +
            page_index.to_bytes(8, 'little'))

with open('ref1.log', 'wb') as f:
    for i in range(200):
        entry_bytes = log_entry_to_bytes(i, 0, 0, 0, i)
        f.write(entry_bytes)
        
with open('pred1.log', 'wb') as f:
    for i in range(200):
        entry_bytes = log_entry_to_bytes(i, 0, 0, 0, i)
        f.write(entry_bytes)