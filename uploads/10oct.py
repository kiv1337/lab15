import math
import matplotlib.pyplot as plt


def normal_pdf(x, mu=0, sigma=1):
    sqrt_two_pi = math.sqrt(2 * math.pi)
    return (math.exp(-(x - mu) ** 2 / 2 / sigma ** 2) / (sqrt_two_pi * sigma))


xs = [x / 10.0 for x in range(-50, 50)]
plt.plot(xs, [normal_pdf(x, sigma=1) for x in xs], '-', label='мю=0, сигма=1')
plt.plot(xs, [normal_pdf(x, sigma=2) for x in xs], '--', label='мю=0, сигма=2')
plt.plot(xs, [normal_pdf(x, sigma=0.5) for x in xs], ':', label='мю=0, сигма=0.5')
plt.plot(xs, [normal_pdf(x, mu=-1) for x in xs], '-.', label='мю=-1, сигма=1')
plt.legend()
plt.title("Несколько ДФР нормального распределения")
plt.show()
