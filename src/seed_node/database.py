import sys; sys.dont_write_bytecode = True

from json import loads

from sqlite3 import connect
from sqlite3 import Cursor
from typing import Any

def init_peers():
    with connect('peers.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS peers_set (
            version REAL NOT NULL,
            services TEXT NOT NULL,
            ipv4_address TEXT NOT NULL,
            port INT NOT NULL,
            node_id TEXT NOT NULL
        )
        ''')

def read_db(cursor : Cursor, table : str, cols, params='') -> Cursor:
    cursor.execute(f"SELECT {','.join(cols)} FROM {table}", params)
 
    return cursor

def create_placeholder_str(cols):
    placeholder_str = ''

    for col in cols:
        placeholder_str += f"'{col}', ?, "

    return placeholder_str[:-2]

def read_db_json(cursor : Cursor, table : str, cols, convert_col, params='') -> Cursor:
    db_values = cursor.execute(f"SELECT {','.join(cols)} FROM {table}", params).fetchall()

    json_values = []

    if cols == '*':
        for item in db_values:
            json_dict = {}

            for col, entry in zip(cursor.description, item):
                if col[0] == convert_col:
                    converted_string = loads(entry)
                    json_dict.update({col[0] : converted_string})

                else:
                    json_dict.update({col[0] : entry})

            json_values.append(json_dict)

    else:
        for item in db_values:
            json_dict = {}

            for col, entry in zip(cols, item):
                if col == convert_col:
                    converted_string = loads(entry)
                    json_dict.update({col : converted_string})

                else:
                    json_dict.update({col : entry})

            json_values.append(json_dict)

    return json_values

def get_cursor(db : str) -> Cursor:
    with connect(db) as conn:
        cursor = conn.cursor()
    
    return cursor

def write_db(cursor : Cursor, table : str, cols : tuple, values : tuple) -> Cursor:
    cursor.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(values))})", values)

    cursor.connection.commit()

def get_column_names(cursor : Cursor, table : str):
    columns = cursor.execute(f"PRAGMA table_info({table})").fetchall()

    column_names = [column[1] for column in columns]

    return column_names

def update_db(cursor: Cursor, table: str, primary_key_col : str, new_row: tuple, row_primary_key_val):
    column_names = get_column_names(cursor, table)

    update_query = f"UPDATE {table} SET "

    for column in column_names:
        update_query += f"{column} = ?, "

    update_query = update_query[:-2] # to exclude the unneccesary ", " at the end

    where_condition = f" WHERE {primary_key_col} = {row_primary_key_val}"

    update_query += where_condition

    cursor.execute(update_query, new_row)
    cursor.connection.commit()

def del_db(cursor : Cursor, table : str, params=None) -> Cursor:
    cursor.execute(f'DELETE FROM {table}', params)

    cursor.connection.commit()

def find_table_cols_db(cursor, table):
    cursor.execute(f'PRAGMA table_info({table})')
    cols = cursor.fetchall()
    
    return cols

def append_db(table : str, values : tuple, cursor : Cursor = None) -> None:
    cursor.execute(f'PRAGMA table_info({table})')
    table_info = cursor.fetchall()

    columns = (col[1] for col in table_info)

    write_db(cursor, table, columns, values)

def get_col_last_value(table : str, col : str, cursor : Cursor = None) -> Any:
    last_value = read_db(cursor, f'{table} ORDER BY {col} DESC LIMIT 1', col).fetchone()[0]

    if not last_value: # checks if selection is None
        return 0
    
    return last_value

def get_col_height(table : str, col : str, cursor : Cursor = None, params=None) -> int:
    col_height = read_db(cursor, f'COUNT({col}) FROM {table}', params).fetchone()[0]

    return col_height