from tkinter import Tk, filedialog

root = Tk()
root.withdraw()  # Скрываем основное окно

file_path = filedialog.askopenfilename(title="Выберите файл")
print("Выбранный файл:", file_path)