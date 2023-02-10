import sqlite3
import csv
import threading
import logging
import sys
import datetime
from datetime import datetime

logger = logging.getLogger('rSMBi')


class Database:
    def __init__(self, db_file):
        self.db_file = db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()

    def create_database(self):
        self.connect_database()
        try:
            rsmbi_match_table = """ CREATE TABLE IF NOT EXISTS rsmbi (
                                            id integer PRIMARY KEY AUTOINCREMENT,
                                            file text NOT NULL,
                                            share text NOT NULL,
                                            ip text NOT NULL,
                                            tsFirstFound text NOT NULL,
                                            tsLastFound text NOT NULL,
                                            runTag text NOT NULL,
                                            winClickable text NOT NULL
                                        ); """

            if self.cursor is not None:
                self.create_table(rsmbi_match_table)

        except Exception as e:
            logger.error(
                "Encountered error while creating the database: " + str(e))
            sys.exit(1)

    def exportToCSV(self, tag):
        cursor = self.cursor
        exportQuery = "SELECT * from rsmbi WHERE runTag = '{tag}\'".format(
            tag=tag)

        sr = cursor.execute(exportQuery)
        with open('rsmbi_results.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerows(sr)

    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):

        try:
            self.cursor.execute(create_table_sql)
        except Exception as e:
            logger.error(e)

    def insertFinding(self, filename, share, ip, tag):
        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        # remove the local path tmp path

        filename = '/'.join(filename.split('/')[3:])
        clickable = "\\\\" + ip + "\\" + share + "\\" + filename

        try:
            self.lock.acquire(True)
            cursor = self.cursor

            cursor.execute('SELECT id,file FROM rsmbi WHERE ip = ? AND share = ? AND file = ?', (
                ip, share, filename))

            results = cursor.fetchall()

            if len(results) == 0:

                insertFindingQuery = "INSERT INTO rsmbi (file, share, ip, tsFirstFound, tsLastFound, runTag, winClickable) VALUES (?,?,?,?,?,?,?)"
                cursor.execute(insertFindingQuery,
                               (filename, share, ip, date, date, tag, clickable.replace("/", "\\")))
                self.commit()
            else:

                updateQuery = 'UPDATE rsmbi SET tsLastFound = ? WHERE ip = ? AND share = ? AND file= ?'
                cursor.execute(updateQuery, (date, ip, share,
                               filename))
                self.commit()

                updateQuery = 'UPDATE rsmbi SET runTag = ? WHERE ip = ? AND share = ? AND file= ?'
                cursor.execute(updateQuery, (tag, ip, share,
                               filename))

        except Exception as e:
            logger.error("Error while updating database: " + str(e))
            self.lock.release()
        finally:
            self.lock.release()
