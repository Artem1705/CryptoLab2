"""
Графический интерфейс для демонстрации порядка постановки и проверки
электронной цифровой подписи (ЭЦП) и асимметричного шифрования (RSA).
Лабораторная работа: «Разработка схемы динамического пароля. Электронная цифровая подпись».

Реализует два окна в точности по скриншотам задания:
- Окно 1: «Отправитель»
- Окно 2: «Получатель»
"""

import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional, List

# Подключение криптографического ядра RSA
try:
    from rsa_core import (
        generate_rsa_keypair,
        encrypt_message,
        decrypt_message,
        sign_message,
        verify_signature
    )
except ImportError:
    from .rsa_core import (
        generate_rsa_keypair,
        encrypt_message,
        decrypt_message,
        sign_message,
        verify_signature
    )


class DigitalSignatureApp:
    def __init__(self):
        # Главное окно (Отправитель)
        self.root_sender = tk.Tk()
        self.root_sender.title("Отправитель")
        self.root_sender.geometry("570x430+40+120")
        self.root_sender.resizable(True, True)

        # Второе окно (Получатель)
        self.root_receiver = tk.Toplevel(self.root_sender)
        self.root_receiver.title("Получатель")
        self.root_receiver.geometry("570x430+640+120")
        self.root_receiver.resizable(True, True)

        # Закрытие обоих окон при закрытии одного
        self.root_sender.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root_receiver.protocol("WM_DELETE_WINDOW", self.on_close)

        # Состояния ключей Отправителя
        self.sender_e: Optional[int] = None
        self.sender_d: Optional[int] = None
        self.sender_n: Optional[int] = None

        # Состояния ключей Получателя
        self.receiver_e: Optional[int] = None
        self.receiver_d: Optional[int] = None
        self.receiver_n: Optional[int] = None

        # Передаваемые пакеты данных (шифртекст и подпись)
        self.encrypted_blocks: Optional[List[int]] = None
        self.digital_signature: Optional[int] = None
        self.raw_message_text: str = ""

        # Построение интерфейсов
        self._build_sender_window()
        self._build_receiver_window()

    def on_close(self):
        self.root_sender.destroy()

    # ==========================================================================
    # ИНТЕРФЕЙС ОКНА «ОТПРАВИТЕЛЬ»
    # ==========================================================================
    def _build_sender_window(self):
        # Главное меню
        menubar = tk.Menu(self.root_sender)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Очистить поля", command=self._clear_sender)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)

        about_menu = tk.Menu(menubar, tearoff=0)
        about_menu.add_command(label="О программе...", command=self._show_about)
        menubar.add_cascade(label="О программе...", menu=about_menu)
        self.root_sender.config(menu=menubar)

        # Верхняя панель ключей
        top_frame = tk.Frame(self.root_sender, padx=10, pady=8)
        top_frame.pack(fill=tk.X)

        # Колонка слева: «Для подписи»
        sig_frame = tk.Frame(top_frame)
        sig_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(sig_frame, text="Для подписи", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        tk.Label(sig_frame, text="Открытый ключ:").grid(row=1, column=0, sticky="w", padx=(0, 4))
        self.entry_send_sig_e = tk.Entry(sig_frame, width=22)
        self.entry_send_sig_e.grid(row=1, column=1, sticky="w", pady=2)

        tk.Label(sig_frame, text="N:").grid(row=2, column=0, sticky="w", padx=(0, 4))
        self.entry_send_sig_n = tk.Entry(sig_frame, width=22)
        self.entry_send_sig_n.grid(row=2, column=1, sticky="w", pady=2)

        # Колонка по центру: «Для сообщения»
        msg_key_frame = tk.Frame(top_frame)
        msg_key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(msg_key_frame, text="Для сообщения", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        tk.Label(msg_key_frame, text="Открытый ключ:").grid(row=1, column=0, sticky="w", padx=(0, 4))
        self.entry_send_msg_e = tk.Entry(msg_key_frame, width=22)
        self.entry_send_msg_e.grid(row=1, column=1, sticky="w", pady=2)

        tk.Label(msg_key_frame, text="N:").grid(row=2, column=0, sticky="w", padx=(0, 4))
        self.entry_send_msg_n = tk.Entry(msg_key_frame, width=22)
        self.entry_send_msg_n.grid(row=2, column=1, sticky="w", pady=2)

        # Колонка справа: Кнопки «Послать» и «Получить» (как на скриншоте)
        transfer_btn_frame = tk.Frame(top_frame)
        transfer_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))

        btn_send_transfer = tk.Button(transfer_btn_frame, text="Послать", width=10, command=self._sender_send_action)
        btn_send_transfer.pack(side=tk.TOP, pady=2)

        btn_get_transfer = tk.Button(transfer_btn_frame, text="Получить", width=10, command=self._sender_receive_keys)
        btn_get_transfer.pack(side=tk.TOP, pady=2)

        # Панель действий и надпись «Окно сообщения»
        mid_frame = tk.Frame(self.root_sender, padx=10, pady=4)
        mid_frame.pack(fill=tk.X)

        tk.Label(mid_frame, text="Окно сообщения").pack(side=tk.LEFT, padx=(0, 10))

        btn_gen_keys = tk.Button(mid_frame, text="Сформировать ключи", command=self._sender_generate_keys)
        btn_gen_keys.pack(side=tk.LEFT, padx=4)

        btn_encrypt_sign = tk.Button(mid_frame, text="Закодировать и подписать", command=self._sender_encrypt_and_sign)
        btn_encrypt_sign.pack(side=tk.LEFT, padx=4)

        # Текстовое поле ввода сообщения
        text_frame = tk.Frame(self.root_sender, padx=10, pady=10)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.txt_sender = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_sender.pack(fill=tk.BOTH, expand=True)
        self.txt_sender.insert(tk.END, "Привет")

    # ==========================================================================
    # ИНТЕРФЕЙС ОКНА «ПОЛУЧАТЕЛЬ»
    # ==========================================================================
    def _build_receiver_window(self):
        menubar = tk.Menu(self.root_receiver)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Очистить поля", command=self._clear_receiver)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)
        self.root_receiver.config(menu=menubar)

        top_frame = tk.Frame(self.root_receiver, padx=10, pady=8)
        top_frame.pack(fill=tk.X)

        # Колонка слева: «Для сообщения»
        msg_key_frame = tk.Frame(top_frame)
        msg_key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(msg_key_frame, text="Для сообщения", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        tk.Label(msg_key_frame, text="Открытый ключ:").grid(row=1, column=0, sticky="w", padx=(0, 4))
        self.entry_rec_msg_e = tk.Entry(msg_key_frame, width=22)
        self.entry_rec_msg_e.grid(row=1, column=1, sticky="w", pady=2)

        tk.Label(msg_key_frame, text="N:").grid(row=2, column=0, sticky="w", padx=(0, 4))
        self.entry_rec_msg_n = tk.Entry(msg_key_frame, width=22)
        self.entry_rec_msg_n.grid(row=2, column=1, sticky="w", pady=2)

        # Колонка справа: «Для подписи»
        sig_frame = tk.Frame(top_frame)
        sig_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(sig_frame, text="Для подписи", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        tk.Label(sig_frame, text="Открытый ключ:").grid(row=1, column=0, sticky="w", padx=(0, 4))
        self.entry_rec_sig_e = tk.Entry(sig_frame, width=22)
        self.entry_rec_sig_e.grid(row=1, column=1, sticky="w", pady=2)

        tk.Label(sig_frame, text="N:").grid(row=2, column=0, sticky="w", padx=(0, 4))
        self.entry_rec_sig_n = tk.Entry(sig_frame, width=22)
        self.entry_rec_sig_n.grid(row=2, column=1, sticky="w", pady=2)

        # Панель действий Получателя
        mid_frame = tk.Frame(self.root_receiver, padx=10, pady=4)
        mid_frame.pack(fill=tk.X)

        tk.Label(mid_frame, text="Окно сообщения").pack(side=tk.LEFT, padx=(0, 10))

        btn_gen_keys = tk.Button(mid_frame, text="Сформировать ключи", command=self._receiver_generate_keys)
        btn_gen_keys.pack(side=tk.LEFT, padx=4)

        btn_send = tk.Button(mid_frame, text="Послать", width=10, command=self._receiver_send_keys)
        btn_send.pack(side=tk.LEFT, padx=4)

        btn_verify = tk.Button(mid_frame, text="Проверить", width=10, command=self._receiver_verify_and_decrypt)
        btn_verify.pack(side=tk.LEFT, padx=4)

        # Текстовое поле сообщения
        text_frame = tk.Frame(self.root_receiver, padx=10, pady=10)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.txt_receiver = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_receiver.pack(fill=tk.BOTH, expand=True)

    # ==========================================================================
    # ЛОГИКА РАБОТЫ АЛГОРИТМА И ОБРАБОТЧИКИ СОБЫТИЙ
    # ==========================================================================

    def _sender_generate_keys(self):
        """1. Генерация ключей Отправителя (для подписи)"""
        e, d, n = generate_rsa_keypair(bits=31)
        self.sender_e, self.sender_d, self.sender_n = e, d, n

        self.entry_send_sig_e.delete(0, tk.END)
        self.entry_send_sig_e.insert(0, str(e))

        self.entry_send_sig_n.delete(0, tk.END)
        self.entry_send_sig_n.insert(0, str(n))

        messagebox.showinfo("Отправитель", "Ключевая пара для подписи успешно сформирована!\n"
                                           f"Открытый ключ e: {e}\nМодуль N: {n}")

    def _receiver_generate_keys(self):
        """2. Генерация ключей Получателя (для шифрования сообщений)"""
        e, d, n = generate_rsa_keypair(bits=31)
        self.receiver_e, self.receiver_d, self.receiver_n = e, d, n

        self.entry_rec_msg_e.delete(0, tk.END)
        self.entry_rec_msg_e.insert(0, str(e))

        self.entry_rec_msg_n.delete(0, tk.END)
        self.entry_rec_msg_n.insert(0, str(n))

        messagebox.showinfo("Получатель", "Ключевая пара для шифрования сообщений сформирована!\n"
                                          f"Открытый ключ e: {e}\nМодуль N: {n}")

    def _receiver_send_keys(self):
        """Получатель передает свой открытый ключ Отправителю (в блок 'Для сообщения')"""
        if not self.receiver_e or not self.receiver_n:
            messagebox.showwarning("Внимание", "Сначала сформируйте ключи Получателя!")
            return

        self.entry_send_msg_e.delete(0, tk.END)
        self.entry_send_msg_e.insert(0, str(self.receiver_e))

        self.entry_send_msg_n.delete(0, tk.END)
        self.entry_send_msg_n.insert(0, str(self.receiver_n))

        messagebox.showinfo("Передача ключей", "Открытый ключ получателя для шифрования передан отправителю!")

    def _sender_receive_keys(self):
        """Отправитель запрашивает открытый ключ Получателя"""
        self._receiver_send_keys()

    def _sender_send_action(self):
        """
        Кнопка 'Послать' в окне Отправителя:
        1. Если ключи получателю еще не переданы, передает открытый ключ подписи.
        2. Если сообщение закодировано, пересылает зашифрованное сообщение и ЭЦП.
        """
        # Передаем открытый ключ подписи получателю
        if self.sender_e and self.sender_n:
            self.entry_rec_sig_e.delete(0, tk.END)
            self.entry_rec_sig_e.insert(0, str(self.sender_e))

            self.entry_rec_sig_n.delete(0, tk.END)
            self.entry_rec_sig_n.insert(0, str(self.sender_n))

        if self.encrypted_blocks is not None and self.digital_signature is not None:
            # Пересылаем зашифрованные данные в окно получателя
            self.txt_receiver.delete("1.0", tk.END)
            blocks_preview = " ".join(str(b) for b in self.encrypted_blocks[:10])
            self.txt_receiver.insert(tk.END, f"[ЗАШИФРОВАННЫЙ ДОКУМЕНТ]\n{blocks_preview} ...\n\n"
                                            f"[ЭЛЕКТРОННАЯ ЦИФРОВАЯ ПОДПИСЬ (ЭЦП)]:\n{self.digital_signature}\n\n"
                                            f"(Нажмите 'Проверить' для расшифрования и верификации)")
            messagebox.showinfo("Отправитель", "Зашифрованное сообщение и цифровая подпись успешно отправлены Получателю!")
        else:
            messagebox.showinfo("Отправитель", "Открытый ключ подписи отправителя передан получателю!")

    def _sender_encrypt_and_sign(self):
        """Шифрование исходного сообщения и наложение ЭЦП"""
        message = self.txt_sender.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Внимание", "Введите текст сообщения в поле 'Окно сообщения'!")
            return

        # Проверяем наличие ключа подписи отправителя
        if not self.sender_d or not self.sender_n:
            messagebox.showwarning("Внимание", "Сначала сформируйте ключи Отправителя (для подписи)!")
            return

        # Проверяем наличие открытого ключа получателя для шифрования
        rec_e_str = self.entry_send_msg_e.get().strip()
        rec_n_str = self.entry_send_msg_n.get().strip()

        if not rec_e_str or not rec_n_str:
            # Если еще не скопирован, пробуем взять у получателя
            if self.receiver_e and self.receiver_n:
                self._receiver_send_keys()
                rec_e_str = str(self.receiver_e)
                rec_n_str = str(self.receiver_n)
            else:
                messagebox.showwarning("Внимание", "Отсутствует открытый ключ Получателя для шифрования!\n"
                                                   "Сформируйте ключи в окне Получателя и нажмите 'Послать'.")
                return

        rec_e = int(rec_e_str)
        rec_n = int(rec_n_str)

        self.raw_message_text = message

        # 1. Шифрование открытым ключом получателя: C = M^e mod n
        self.encrypted_blocks = encrypt_message(message, rec_e, rec_n)

        # 2. Формирование ЭЦП закрытым ключом отправителя: S = H(M)^d mod n
        self.digital_signature = sign_message(message, self.sender_d, self.sender_n)

        # Визуализация в окне отправителя
        messagebox.showinfo("Результат",
                            "Сообщение успешно закодировано и подписано ЭЦП!\n\n"
                            f"Длина шифртекста: {len(self.encrypted_blocks)} блоков.\n"
                            f"Значение ЭЦП: {self.digital_signature}\n\n"
                            "Теперь нажмите кнопку 'Послать'.")

    def _receiver_verify_and_decrypt(self):
        """Получатель выполняет расшифрование сообщения и проверку подписи"""
        if self.encrypted_blocks is None or self.digital_signature is None:
            messagebox.showwarning("Внимание", "Сообщение еще не получено от Отправителя!")
            return

        if not self.receiver_d or not self.receiver_n:
            messagebox.showwarning("Внимание", "Отсутствует секретный ключ Получателя для расшифрования!")
            return

        send_e_str = self.entry_rec_sig_e.get().strip()
        send_n_str = self.entry_rec_sig_n.get().strip()

        if not send_e_str or not send_n_str:
            messagebox.showwarning("Внимание", "Отсутствует открытый ключ Отправителя для проверки подписи!")
            return

        send_e = int(send_e_str)
        send_n = int(send_n_str)

        # 1. Расшифрование секретным ключом получателя: M = C^d mod n
        decrypted_text = decrypt_message(self.encrypted_blocks, self.receiver_d, self.receiver_n)

        # 2. Проверка ЭЦП открытым ключом отправителя: h == S^e mod n
        is_valid = verify_signature(decrypted_text, self.digital_signature, send_e, send_n)

        self.txt_receiver.delete("1.0", tk.END)
        self.txt_receiver.insert(tk.END, decrypted_text)

        if is_valid:
            messagebox.showinfo(
                "Проверка ЭЦП",
                "УСПЕШНАЯ ПРОВЕРКА ЭЦП!\n\n"
                f"1. Электронная цифровая подпись: ПОДЛИННАЯ.\n"
                f"2. Авторство отправителя: ПОДТВЕРЖДЕНО.\n"
                f"3. Целостность документа: НЕ НАРУШЕНА.\n\n"
                f"Восстановленный текст:\n'{decrypted_text}'"
            )
        else:
            messagebox.showerror(
                "Ошибка ЭЦП",
                "ВНИМАНИЕ: Электронная цифровая подпись НЕВЕРНА!\n"
                "Документ был искажен или подписан другим ключом."
            )

    def _clear_sender(self):
        self.entry_send_sig_e.delete(0, tk.END)
        self.entry_send_sig_n.delete(0, tk.END)
        self.entry_send_msg_e.delete(0, tk.END)
        self.entry_send_msg_n.delete(0, tk.END)
        self.txt_sender.delete("1.0", tk.END)

    def _clear_receiver(self):
        self.entry_rec_msg_e.delete(0, tk.END)
        self.entry_rec_msg_n.delete(0, tk.END)
        self.entry_rec_sig_e.delete(0, tk.END)
        self.entry_rec_sig_n.delete(0, tk.END)
        self.txt_receiver.delete("1.0", tk.END)

    def _show_about(self):
        messagebox.showinfo(
            "О программе",
            "Лабораторная работа:\n"
            "«Разработка схемы динамического пароля. Электронная цифровая подпись»\n\n"
            "Программа моделирует защищенный информационный обмен между Отправителем и Получателем:\n"
            "• Асимметричное шифрование сообщения по алгоритму RSA;\n"
            "• Формирование и проверку электронной цифровой подписи (ЭЦП);\n"
            "• Гарантию конфиденциальности, целостности и неотрекаемости авторства."
        )

    def run(self):
        self.root_sender.mainloop()


if __name__ == "__main__":
    app = DigitalSignatureApp()
    app.run()
