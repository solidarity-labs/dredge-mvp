from tabulate import tabulate
from utils.constants import default_file_name, default_output_folder
import csv
import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, data, file_name, csv=False, json=False, tabulated=False):
        self.data = data
        self.file_name = file_name
        self.csv = csv
        self.json = json
        self.tabulated = tabulated
        self.destination_folder = default_output_folder
        self.default_file_name = default_file_name


    def reporter(self):
        if self.tabulated:
            self.tabulated_reporter()
        
        if self.csv:
            output_file = self.csv_reporter()
            print(f'CSV file "{output_file}" has been created successfully.')
            print()
        
        if self.json == "json":
            pass
        
       
    def tabulated_reporter(self):
        table = tabulate(self.data, headers="firstrow", tablefmt="fancy_grid")
        print(table)
        print()


    def csv_reporter(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.destination_folder) 
        except FileNotFoundError as e:
            os.mkdir(self.destination_folder)
            os.chdir(self.destination_folder)

        # Open the CSV file in write mode
        output_file = f'{self.file_name}_{self.default_file_name}_{datetime.now():%Y-%m-%d}.csv'
        
        with open(output_file, mode='a', newline='') as file:

            # Create a CSV writer object
            writer = csv.writer(file)

            # Write the data to the CSV file
            writer.writerows(self.data)

        os.chdir(cwd)
        return output_file


    def aws_csv_reporter(self):
        if self.data:
            cwd = os.getcwd()
            try:
                os.chdir(default_output_folder) 
            except FileNotFoundError as e:
                os.mkdir(default_output_folder)
                os.chdir(default_output_folder)

            # Open the CSV file in write mode
            output_file = f'{self.file_name}_{default_file_name}_{datetime.now():%Y-%m-%d}.csv'
            
            with open(output_file, mode='a', newline='') as file:

                # Create a CSV writer object
                writer = csv.writer(file)

                # Write the data to the CSV file
                writer.writerow(self.data)

            os.chdir(cwd)
            return output_file