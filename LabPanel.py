import os
import wx
import Lab1
import Lab2
import Lab3
import Lab4
import Lab5
import random


class MainFrame(wx.Frame):
    def __init__(self, parent, title):
        super(MainFrame, self).__init__(parent, title=title, size=(500, 600))

        notebook = wx.Notebook(self)

        # Вкладка 1
        self.tab1 = wx.Panel(notebook)
        notebook.AddPage(self.tab1, "Ген. вип. чисел (Лаб. 1)")

        self.n_label = wx.StaticText(self.tab1, label="Кількість чисел (n):")
        self.n_input = wx.TextCtrl(self.tab1)

        self.generate_button = wx.Button(self.tab1, label="Згенерувати")
        self.save_button = wx.Button(self.tab1, label="Зберегти до файлу")
        self.save_button.Disable()
        self.test_lcg_button = wx.Button(self.tab1, label="Тестувати генератор псевдовипадкових чисел")

        self.result_text = wx.TextCtrl(self.tab1, style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.result_label = wx.StaticText(self.tab1, label="\n\n\n\n")

        vbox1 = wx.BoxSizer(wx.VERTICAL)

        vbox1.Add(self.n_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox1.Add(self.n_input, flag=wx.ALL | wx.ALIGN_CENTER, border=10, proportion=0)
        vbox1.Add(self.generate_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10, proportion=0)
        vbox1.Add(self.result_text, flag=wx.ALL | wx.EXPAND, border=10, proportion=1)
        vbox1.Add(self.save_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10, proportion=0)
        vbox1.Add(self.test_lcg_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10, proportion=0)
        vbox1.Add(self.result_label, flag=wx.ALL | wx.EXPAND, border=10, proportion=0)

        self.tab1.SetSizer(vbox1)

        # Вкладка 2
        self.tab2 = wx.ScrolledWindow(notebook, style=wx.VSCROLL | wx.HSCROLL)
        self.tab2.SetScrollRate(0, 5)
        notebook.AddPage(self.tab2, "MD5 Хешування (Лаб. 2)")

        self.input_message_label = wx.StaticText(self.tab2, label="Початкове повідомлення:")
        self.input_message = wx.TextCtrl(self.tab2)

        self.or_message_label = wx.StaticText(self.tab2, label="або")
        self.load_file_button = wx.Button(self.tab2, label="Завантажити файл")
        self.hash_button = wx.Button(self.tab2, label="Запустити хешування MD5")
        self.save_hash_button = wx.Button(self.tab2, label="Зберегти хеш до файлу")
        self.save_hash_button.Disable()
        self.test_md5_button = wx.Button(self.tab2, label="Тестувати MD5")

        self.input_hash_label = wx.StaticText(self.tab2, label="Введіть хеш для перевірки:")
        self.input_hash = wx.TextCtrl(self.tab2)
        self.check_hash_button = wx.Button(self.tab2, label="Перевірити хеш (Вставте ваш файл для перевірки )")

        self.hash_output = wx.TextCtrl(self.tab2, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.test_result_label = wx.StaticText(self.tab2, label="")

        vbox2 = wx.BoxSizer(wx.VERTICAL)

        vbox2.Add(self.input_message_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        self.input_message.SetMinSize((300, -1))
        vbox2.Add(self.input_message, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.Add(self.or_message_label, flag=wx.ALL | wx.ALIGN_CENTER, border=0)
        vbox2.Add(self.load_file_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.Add(self.hash_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        self.hash_output.SetMinSize((300, -1))
        vbox2.Add(self.hash_output, flag=wx.ALL | wx.EXPAND, border=10)
        vbox2.Add(self.save_hash_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.AddSpacer(20)
        vbox2.Add(self.test_md5_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.Add(self.test_result_label, flag=wx.ALL | wx.EXPAND, border=10)
        vbox2.AddSpacer(20)
        vbox2.Add(self.input_hash_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.Add(self.input_hash, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox2.Add(self.check_hash_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)

        self.tab2.SetSizer(vbox2)

        # Вкладка 3 для RC5
        self.tab3 = wx.Panel(notebook)
        notebook.AddPage(self.tab3, "RC5 (Лаб. 3)")

        self.passphrase_label = wx.StaticText(self.tab3, label="Парольна фраза:")
        self.passphrase_input = wx.TextCtrl(self.tab3)
        self.encrypt_button = wx.Button(self.tab3, label="Шифрувати")
        self.decrypt_button = wx.Button(self.tab3, label="Дешифрувати")

        vbox3 = wx.BoxSizer(wx.VERTICAL)
        vbox3.Add(self.passphrase_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox3.Add(self.passphrase_input, flag=wx.ALL | wx.EXPAND, border=10)
        vbox3.Add(self.encrypt_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox3.Add(self.decrypt_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)

        self.tab3.SetSizer(vbox3)

        # Вкладка 4 для RSA
        self.tab4 = wx.Panel(notebook)
        notebook.AddPage(self.tab4, "RSA (Лаб. 4)")

        self.private_key_label = wx.StaticText(self.tab4, label="Приватний ключ:")
        self.private_key_path = wx.TextCtrl(self.tab4)
        self.browse_private_key_button = wx.Button(self.tab4, label="Обрати приватний ключ")
        self.public_key_label = wx.StaticText(self.tab4, label="Публічний ключ:")
        self.public_key_path = wx.TextCtrl(self.tab4)
        self.browse_public_key_button = wx.Button(self.tab4, label="Обрати публічний ключ")
        self.generate_keys_button = wx.Button(self.tab4, label="Згенерувати ключі")
        self.encrypt_rsa_button = wx.Button(self.tab4, label="Шифрувати")
        self.decrypt_rsa_button = wx.Button(self.tab4, label="Дешифрувати")
        self.result_text = wx.TextCtrl(self.tab4, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.save_button = wx.Button(self.tab4, label="Зберегти результат")
        self.save_button.Disable()

        vbox4 = wx.BoxSizer(wx.VERTICAL)

        vbox4.Add(self.private_key_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.private_key_path, flag=wx.ALL | wx.EXPAND, border=10)
        vbox4.Add(self.browse_private_key_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.public_key_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.public_key_path, flag=wx.ALL | wx.EXPAND, border=10)
        vbox4.Add(self.browse_public_key_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.generate_keys_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.encrypt_rsa_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.decrypt_rsa_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox4.Add(self.result_text, flag=wx.ALL | wx.EXPAND, border=10)
        vbox4.Add(self.save_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)

        self.tab4.SetSizer(vbox4)

        # Вкладка 5 для RSA та RC5
        self.tab5 = wx.Panel(notebook)
        notebook.AddPage(self.tab5, "RSA та RC5 (Лаб. 4)")

        self.input_file_label_ = wx.StaticText(self.tab5, label="Вхідний файл:")
        self.input_file_path_ = wx.TextCtrl(self.tab5)
        self.browse_input_file_button_ = wx.Button(self.tab5, label="Обрати файл")
        self.private_key_label_ = wx.StaticText(self.tab5, label="Приватний ключ (RSA):")
        self.browse_private_key_button_ = wx.Button(self.tab5, label="Обрати приватний ключ")
        self.private_key_path_ = wx.TextCtrl(self.tab5)
        self.public_key_label_ = wx.StaticText(self.tab5, label="Публічний ключ (RSA):")
        self.browse_public_key_button_ = wx.Button(self.tab5, label="Обрати публічний ключ")
        self.public_key_path_ = wx.TextCtrl(self.tab5)
        self.passphrase_label_ = wx.StaticText(self.tab5, label="Парольна фраза (RC5):")
        self.passphrase_input_ = wx.TextCtrl(self.tab5)
        self.benchmark_button_ = wx.Button(self.tab5, label="Порівняти продуктивність")
        self.result_label_ = wx.StaticText(self.tab5, label="Результат:")

        tab5 = wx.BoxSizer(wx.VERTICAL)
        tab5.Add(self.input_file_label_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.input_file_path_, flag=wx.ALL | wx.EXPAND, border=10)
        tab5.Add(self.browse_input_file_button_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.private_key_label_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.private_key_path_, flag=wx.ALL | wx.EXPAND, border=10)
        tab5.Add(self.browse_private_key_button_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.public_key_label_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.public_key_path_, flag=wx.ALL | wx.EXPAND, border=10)
        tab5.Add(self.browse_public_key_button_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.passphrase_label_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.passphrase_input_, flag=wx.ALL | wx.EXPAND, border=10)
        tab5.Add(self.benchmark_button_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        tab5.Add(self.result_label_, flag=wx.ALL | wx.ALIGN_CENTER, border=10)

        self.tab5.SetSizer(tab5)

        # Вкладка 6
        self.tab6 = wx.Panel(notebook)
        notebook.AddPage(self.tab6, "DSS (Лаб. 5)")

        self.generate_keys_button = wx.Button(self.tab6, label="Згенерувати ключі")
        self.sign_button = wx.Button(self.tab6, label="Підписати повідомлення")
        self.verify_button = wx.Button(self.tab6, label="Перевірити підпис")
        self.message_label = wx.StaticText(self.tab6, label="Повідомлення:")
        self.message_input = wx.TextCtrl(self.tab6)
        self.signature_label = wx.StaticText(self.tab6, label="Підпис (Hex):")
        self.signature_input = wx.TextCtrl(self.tab6)
        self.result_label = wx.StaticText(self.tab6, label="Результат:")

        vbox6 = wx.BoxSizer(wx.VERTICAL)
        vbox6.Add(self.generate_keys_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox6.Add(self.message_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox6.Add(self.message_input, flag=wx.ALL | wx.EXPAND, border=10)
        vbox6.Add(self.sign_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox6.Add(self.signature_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox6.Add(self.signature_input, flag=wx.ALL | wx.EXPAND, border=10)
        vbox6.Add(self.verify_button, flag=wx.ALL | wx.ALIGN_CENTER, border=10)
        vbox6.Add(self.result_label, flag=wx.ALL | wx.ALIGN_CENTER, border=10)

        self.tab6.SetSizer(vbox6)

        # Lab1
        self.generate_button.Bind(wx.EVT_BUTTON, self.on_generate_numbers)
        self.save_button.Bind(wx.EVT_BUTTON, self.on_save_numbers)
        self.test_lcg_button.Bind(wx.EVT_BUTTON, self.on_calculate_chezaro)

        # Lab2
        self.load_file_button.Bind(wx.EVT_BUTTON, self.on_load_file)
        self.hash_button.Bind(wx.EVT_BUTTON, self.on_hash_md5)
        self.save_hash_button.Bind(wx.EVT_BUTTON, self.on_save_hash)
        self.test_md5_button.Bind(wx.EVT_BUTTON, self.on_test_md5)
        self.check_hash_button.Bind(wx.EVT_BUTTON, self.on_check_hash)

        # Lab3
        self.encrypt_button.Bind(wx.EVT_BUTTON, self.on_encrypt_rc5)
        self.decrypt_button.Bind(wx.EVT_BUTTON, self.on_decrypt_rc5)

        # Lab4
        self.browse_private_key_button.Bind(wx.EVT_BUTTON, self.on_browse_private_key)
        self.browse_public_key_button.Bind(wx.EVT_BUTTON, self.on_browse_public_key)
        self.generate_keys_button.Bind(wx.EVT_BUTTON, self.on_generate_rsa_keys)
        self.encrypt_rsa_button.Bind(wx.EVT_BUTTON, self.on_encrypt_rsa)
        self.decrypt_rsa_button.Bind(wx.EVT_BUTTON, self.on_decrypt_rsa)
        self.save_button.Bind(wx.EVT_BUTTON, self.on_save_result)

        # Lab 4
        self.browse_input_file_button_.Bind(wx.EVT_BUTTON, self.on_browse_input_file)
        self.browse_private_key_button_.Bind(wx.EVT_BUTTON, self.on_browse_private_key)
        self.browse_public_key_button_.Bind(wx.EVT_BUTTON, self.on_browse_public_key)
        self.benchmark_button_.Bind(wx.EVT_BUTTON, self.on_benchmark)
        self.generated_numbers = None
        self.Show()

        # Lab 5
        self.generate_keys_button.Bind(wx.EVT_BUTTON, self.on_generate_keys)
        self.sign_button.Bind(wx.EVT_BUTTON, self.on_sign_message)
        self.verify_button.Bind(wx.EVT_BUTTON, self.on_verify_signature)

    def evaluate_expression(self, expr):
        try:
            return eval(expr)
        except Exception as e:
            wx.MessageBox(f"Неправильний вираз: {e}", "Помилка", wx.OK | wx.ICON_ERROR)
            return None

    def on_generate_numbers(self, event):
        n = self.evaluate_expression(self.n_input.GetValue())
        if n is None or not isinstance(n, int) or n <= 0:
            wx.MessageBox("Будь ласка, введіть додатне ціле число для n.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        m = Lab1.config["m"]
        a = Lab1.config["a"]
        c = Lab1.config["c"]
        x0 = Lab1.config["x0"]
        self.generated_numbers = Lab1.lcg(m, a, c, x0, n)

        self.result_text.SetValue(" ".join(map(str, self.generated_numbers)))

        self.save_button.Enable()

    def on_save_numbers(self, event):
        if self.generated_numbers:
            n = self.evaluate_expression(self.n_input.GetValue())
            Lab1.save_to_file(self.generated_numbers, n)
            wx.MessageBox(f"{n} чисел збережено до файлу random_numbers.txt", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_calculate_chezaro(self, event):
        if self.generated_numbers is None:
            wx.MessageBox("Спочатку згенеруйте числа.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        numbers_period = Lab1.find_period(self.generated_numbers)
        result_output = f"\nПеріод послідовності: {numbers_period}\n"

        pi_estimate = Lab1.Chezaro_theorem(self.generated_numbers)
        if pi_estimate:
            result_output += f"\nОцінене значення π для LCG: {pi_estimate}\n"
        else:
            result_output += "\nНеможливо оцінити значення π для LCG.\n"

        system_random_numbers = [random.randint(0, Lab1.config["m"] - 1) for _ in range(len(self.generated_numbers))]
        system_pi_estimate = Lab1.Chezaro_theorem(system_random_numbers)
        result_output += f"Оцінене значення π для системного генератора: {system_pi_estimate}\n"

        self.result_label.SetLabel(result_output)

    def on_load_file(self, event):
        with wx.FileDialog(self, "Відкрити файл", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:

            if file_dialog.ShowModal() == wx.ID_OK:
                filepath = file_dialog.GetPath()
                try:
                    self.loaded_file_path = filepath
                    wx.MessageBox(f"Файл: {filepath} завантажений успішно!", "Успіх", wx.OK | wx.ICON_INFORMATION)

                    self.input_message.Disable()

                except Exception as e:
                    wx.MessageBox(f"Помилка при відкритті файлу: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

    def on_hash_md5(self, event):
        if hasattr(self, 'loaded_file_path'):
            try:
                with wx.BusyInfo("Зачекайте, файл хешується..."):
                    self.md5_hash = Lab2.md5_for_data(self.loaded_file_path)

                wx.MessageBox(f"Файл захешовано успішно!", "Успіх", wx.OK | wx.ICON_INFORMATION)
                self.input_message.Enable()

            except Exception as e:
                wx.MessageBox(f"Помилка при хешуванні файлу: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

            delattr(self, 'loaded_file_path')

        else:
            message = self.input_message.GetValue()

            self.md5_hash = Lab2.md5_for_data(message, is_file=False)
            wx.MessageBox("Повідомлення захешовано успішно!", "Успіх", wx.OK | wx.ICON_INFORMATION)

        self.hash_output.SetValue(self.md5_hash)
        self.save_hash_button.Enable()

    def on_save_hash(self, event):
        if not hasattr(self, 'md5_hash') or not self.md5_hash:
            wx.MessageBox("Немає хешованого значення для збереження.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        Lab2.save_to_file(self.md5_hash, self.input_message.GetValue())
        wx.MessageBox(f"Хешоване значення збережено до файлу .txt", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_test_md5(self, event):
        test_cases = {
            "": "d41d8cd98f00b204e9800998ecf8427e",
            "a": "0cc175b9c0f1b6a831c399e269772661",
            "abc": "900150983cd24fb0d6963f7d28e17f72",
            "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
        }

        results = []
        for message, expected_hash in test_cases.items():
            actual_hash = Lab2.md5_for_data(message, is_file=False)
            match = actual_hash == expected_hash
            results.append(f"Message: {message}, Expected: {expected_hash}, Got: {actual_hash}, Match: {match}")
        self.test_result_label.SetLabel("\n".join(results))

    def on_check_hash(self, event):
        input_hash = self.input_hash.GetValue().strip()
        if not input_hash:
            wx.MessageBox("Будь ласка, введіть хеш для перевірки.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        with wx.FileDialog(self, "Відкрити файл з хешем", wildcard="Text files (*.txt)|*.txt|All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                filepath = file_dialog.GetPath()
                with open(filepath, "r") as file:
                    saved_hash = file.readline().strip().split(":")[-1].strip()

                if input_hash.lower() == saved_hash.lower():
                    wx.MessageBox("Хеші співпадають!", "Успіх", wx.OK | wx.ICON_INFORMATION)
                else:
                    wx.MessageBox("Хеші не співпадають.", "Помилка", wx.OK | wx.ICON_ERROR)

    def generate_iv(self):
        seed = int.from_bytes(self.passphrase_input.GetValue().encode(), "little")
        iv_numbers = Lab1.lcg(2 ** 16, 1103515245, 12345, seed, 1)
        return iv_numbers[0]

    def generate_key_from_passphrase(self, passcode):
        return Lab3.get_key_from_passphrase(passcode, 64)

    def on_encrypt_rc5(self, event):
        passcode = self.passphrase_input.GetValue().strip()
        if not passcode:
            wx.MessageBox("Парольна фраза не може бути порожньою.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        with wx.FileDialog(self, "Виберіть файл для шифрування", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN) as dialog:
            if dialog.ShowModal() == wx.ID_OK:
                input_file = dialog.GetPath()
                output_file = f"{input_file}.enc"
                iv = self.generate_iv()
                key = self.generate_key_from_passphrase(passcode)
                rc5 = Lab3.RC5(16, 12, key)
                with wx.BusyInfo("Зачекайте, файл шифрується..."):
                    rc5.encrypt_file(iv, input_file, output_file)
                wx.MessageBox(f"Файл зашифровано: {output_file}", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_decrypt_rc5(self, event):
        passcode = self.passphrase_input.GetValue().strip()
        if not passcode:
            wx.MessageBox("Парольна фраза не може бути порожньою.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        with wx.FileDialog(self, "Виберіть файл для дешифрування", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN) as dialog:
            if dialog.ShowModal() == wx.ID_OK:
                input_file = dialog.GetPath()
                output_file = f"{input_file}.dec"
                key = self.generate_key_from_passphrase(passcode)
                rc5 = Lab3.RC5(16, 12, key)
                with wx.BusyInfo("Зачекайте, файл дешифрується..."):
                    rc5.decrypt_file(input_file, output_file)
                wx.MessageBox(f"Файл дешифровано: {output_file}", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_generate_rsa_keys(self, event):
        try:
            with wx.DirDialog(self, "Виберіть директорію для збереження ключів",
                              style=wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST) as dir_dialog:
                if dir_dialog.ShowModal() == wx.ID_OK:
                    path = dir_dialog.GetPath()  # Отримуємо шлях до вибраної директорії
                    private_key_path = os.path.join(path, "private_key.pem")
                    public_key_path = os.path.join(path, "public_key.pem")

                    Lab4.generate_rsa_keys(private_key_path, public_key_path)

                    self.private_key_path.SetValue(private_key_path)
                    self.public_key_path.SetValue(public_key_path)

                    wx.MessageBox("Ключі успішно згенеровані!", "Успіх", wx.OK | wx.ICON_INFORMATION)
        except Exception as e:
            wx.MessageBox(f"Помилка під час генерації ключів: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

    def on_browse_private_key(self, event):
        with wx.FileDialog(self, "Обрати приватний ключ", wildcard="PEM files (*.pem)|*.pem|All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                selected_path = file_dialog.GetPath()
                self.private_key_path.SetValue(selected_path)
                self.private_key_path_.SetValue(selected_path)

    def on_browse_public_key(self, event):
        with wx.FileDialog(self, "Обрати публічний ключ", wildcard="PEM files (*.pem)|*.pem|All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                selected_path = file_dialog.GetPath()
                self.public_key_path.SetValue(selected_path)
                self.public_key_path_.SetValue(selected_path)

    def on_encrypt_rsa(self, event):
        with wx.FileDialog(self, "Виберіть файл для шифрування", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                input_file = file_dialog.GetPath()

                public_key_path = self.public_key_path.GetValue()
                if not os.path.exists(public_key_path):
                    wx.MessageBox("Публічний ключ не знайдено.", "Помилка", wx.OK | wx.ICON_ERROR)
                    return

                try:
                    with open(input_file, "rb") as f:
                        plaintext = f.read()

                    encrypted_data = Lab4.rsa_encrypt(plaintext, public_key_path)
                    encrypted_base64 = Lab4.to_base64(encrypted_data)

                    self.result_text.SetValue(encrypted_base64)
                    self.save_button.Enable()
                    self.result_to_save = encrypted_base64

                    wx.MessageBox("Файл успішно зашифровано!", "Успіх", wx.OK | wx.ICON_INFORMATION)

                except Exception as e:
                    wx.MessageBox(f"Помилка під час шифрування: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

    def on_decrypt_rsa(self, event):
        with wx.FileDialog(self, "Виберіть файл для дешифрування", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                input_file = file_dialog.GetPath()

                private_key_path = self.private_key_path.GetValue()
                if not os.path.exists(private_key_path):
                    wx.MessageBox("Приватний ключ не знайдено.", "Помилка", wx.OK | wx.ICON_ERROR)
                    return

                try:
                    with open(input_file, "r") as f:
                        encrypted_base64 = f.read()

                    encrypted_data = Lab4.from_base64(encrypted_base64)

                    decrypted_data = Lab4.rsa_decrypt(encrypted_data, private_key_path)

                    decrypted_text = decrypted_data.decode('utf-8')

                    self.result_text.SetValue(decrypted_text)
                    self.save_button.Enable()
                    self.result_to_save = decrypted_text

                    wx.MessageBox("Файл успішно дешифровано!", "Успіх", wx.OK | wx.ICON_INFORMATION)

                except Exception as e:
                    wx.MessageBox(f"Помилка під час дешифрування: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

    def on_save_result(self, event):
        if not hasattr(self, 'result_to_save') or not self.result_to_save:
            wx.MessageBox("Немає результату для збереження.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        with wx.FileDialog(self, "Зберегти файл", wildcard="Text files (*.txt)|*.txt|All files (*.*)|*.*",
                           style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as save_dialog:
            if save_dialog.ShowModal() == wx.ID_OK:
                output_file = save_dialog.GetPath()
                if not output_file.endswith('.txt'):
                    output_file += '.txt'

                with open(output_file, "w") as f:
                    f.write(self.result_to_save)

                wx.MessageBox("Результат успішно збережено!", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_browse_input_file(self, event):
        with wx.FileDialog(self, "Виберіть вхідний файл", wildcard="All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as file_dialog:
            if file_dialog.ShowModal() == wx.ID_OK:
                self.input_file_path_.SetValue(file_dialog.GetPath())

    def on_benchmark(self, event):
        input_file = self.input_file_path_.GetValue()
        if not input_file or not os.path.exists(input_file):
            wx.MessageBox("Виберіть коректний вхідний файл.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        private_key_path = self.private_key_path.GetValue()
        public_key_path = self.public_key_path.GetValue()
        passphrase = self.passphrase_input.GetValue()

        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            wx.MessageBox("Перевірте шляхи до ключів RSA.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        if not passphrase:
            wx.MessageBox("Введіть парольну фразу для RC5.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        rsa_private, rsa_public = Lab4.read_rsa_keys(private_key_path, public_key_path)

        rc5_key = Lab3.get_key_from_passphrase(passphrase, bit_length=64)
        iv_numbers = Lab1.lcg(2 ** 16, 1103515245, 12345, int.from_bytes(rc5_key, "little"), 1)
        iv = iv_numbers[0]

        try:
            rsa_time, rc5_time = Lab4.benchmark(input_file, rsa_private, rsa_public, rc5_key, iv)
            result_text = (
                f"RSA encryption time: {rsa_time:.4f} seconds\n"
                f"RC5 encryption time: {rc5_time:.4f} seconds\n"
                f"RSA is {rsa_time / rc5_time:.2f} times slower than RC5."
            )
            self.result_label.SetLabel(result_text)
        except Exception as e:
            wx.MessageBox(f"Помилка під час виконання: {e}", "Помилка", wx.OK | wx.ICON_ERROR)

    def on_generate_keys(self, event):
        Lab5.generate_keys()
        wx.MessageBox("Ключі згенеровані та збережені!", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_sign_message(self, event):
        message = self.message_input.GetValue()
        if not message:
            wx.MessageBox("Введіть повідомлення для підпису.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        signature = Lab5.sign_message(message)
        self.signature_input.SetValue(signature)
        wx.MessageBox("Повідомлення успішно підписано!", "Успіх", wx.OK | wx.ICON_INFORMATION)

    def on_verify_signature(self, event):
        message = self.message_input.GetValue()
        signature = self.signature_input.GetValue()

        if not message or not signature:
            wx.MessageBox("Введіть повідомлення та підпис для перевірки.", "Помилка", wx.OK | wx.ICON_ERROR)
            return

        is_valid = Lab5.verify_signature(message, signature)
        result_text = "Підпис дійсний!" if is_valid else "Підпис недійсний."
        self.result_label.SetLabel(result_text)


if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame(None, title="Технології захисту інформації (Лабораторні)")
    app.MainLoop()
