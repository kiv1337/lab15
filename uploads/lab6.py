

multi = int(input("Введите 1-ое число:")) * int(input("Введите 2-ое число:"))

if 10 <= multi and multi <= 99 or -99 <= multi and multi <= -10:
    print(multi, '- двузначное число =)')
else:
    print(multi, '- не является двузначным числом =(')