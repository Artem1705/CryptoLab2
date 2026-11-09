"""
Расчет схемы динамического пароля функциональным методом.
Лабораторная работа: «Разработка схемы динамического пароля. Электронная цифровая подпись».

Формула:
    Y = (X mod 100) * D + W
где:
    X - исходный пароль / собственная дата рождения (например, день или полная дата),
    (X mod 100) - остаток от деления X на 100 (последние 2 цифры числа X),
    D - месяц рождения пользователя (от 1 до 12),
    W - текущий день недели (1 - понедельник, 2 - вторник, ..., 7 - воскресенье).

Паролями для последовательности периодов действия будут:
    Период 1: P_1 = X
    Период 2: P_2 = F(P_1)
    Период 3: P_3 = F(P_2)
    Период 4: P_4 = F(P_3)
    и т.д.
"""

from typing import List, Dict


def calculate_dynamic_password_chain(
    birth_date_x: int,
    birth_month_d: int,
    start_weekday_w: int = 1,
    num_periods: int = 7
) -> List[Dict[str, int]]:
    """
    Вычисляет цепочку динамических паролей для num_periods периодов.
    :param birth_date_x: Исходное число X (дата рождения).
    :param birth_month_d: Месяц рождения D (1..12).
    :param start_weekday_w: Начальный день недели W (1..7).
    :param num_periods: Количество шагов (дней/периодов).
    :return: Список словарей с подробными шагами вычислений.
    """
    chain = []
    current_x = birth_date_x
    weekday_names = [
        "Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"
    ]

    for step in range(1, num_periods + 1):
        weekday = ((start_weekday_w - 1 + (step - 1)) % 7) + 1
        w_name = weekday_names[weekday - 1]
        x_mod_100 = current_x % 100
        next_y = (x_mod_100 * birth_month_d) + weekday

        chain.append({
            "step": step,
            "weekday_num": weekday,
            "weekday_name": w_name,
            "current_password": current_x,
            "x_mod_100": x_mod_100,
            "d_month": birth_month_d,
            "next_password": next_y,
            "formula_str": f"({x_mod_100} * {birth_month_d}) + {weekday} = {next_y}"
        })
        current_x = next_y

    return chain


def print_dynamic_password_table(chain: List[Dict[str, int]]):
    print("=" * 80)
    print("РАСЧЕТ ДИНАМИЧЕСКИХ ПАРОЛЕЙ ПО ФОРМУЛЕ: Y = (X mod 100) * D + W")
    print("=" * 80)
    print(f"{'Период':<8} | {'День недели':<12} | {'Пароль X':<10} | {'X mod 100':<10} | {'D':<3} | {'W':<2} | {'Новый пароль Y':<15}")
    print("-" * 80)
    for row in chain:
        print(f"{row['step']:<8} | {row['weekday_name']:<12} | {row['current_password']:<10} | "
              f"{row['x_mod_100']:<10} | {row['d_month']:<3} | {row['weekday_num']:<2} | {row['next_password']:<15}")
    print("=" * 80)


if __name__ == "__main__":
    # Пример: дата рождения 16 мая (X = 16, D = 5)
    # Если студент хочет задать свой день: можно изменить параметры
    birth_day = 16
    birth_month = 5
    result = calculate_dynamic_password_chain(birth_day, birth_month, start_weekday_w=1, num_periods=7)
    print_dynamic_password_table(result)
