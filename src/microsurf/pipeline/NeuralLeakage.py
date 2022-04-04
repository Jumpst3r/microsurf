import os
import logging
from matplotlib.pyplot import yticks
from mine.models.mine import Mine
from sklearn.model_selection import train_test_split
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import minmax_scale
import torch
from tqdm import tqdm
from microsurf.utils.logger import LOGGING_LEVEL, getLogger
import seaborn as sns
import torch.nn.functional as F
from rich.progress import track
import matplotlib.pyplot as plt

log = getLogger()


class shiftedRELU(nn.Module):
    __constants__ = ["inplace"]
    inplace: bool

    def __init__(self, weights=1, inplace: bool = False):
        super().__init__()
        self.inplace = inplace
        self.weights = weights

    def forward(self, input):
        return F.relu(input - 0.5, inplace=self.inplace)


class MIEstimator(nn.Module):
    def __init__(self, X) -> None:
        super().__init__()
        self.X = X

    def trainEstimator(self, y):
        self.T = nn.Sequential(
            nn.Linear(self.X.shape[1] * 2, 100),
            nn.ReLU(),
            nn.Linear(100, 100),
            nn.ReLU(),
            nn.Linear(100, 1),
        )
        self.mine = Mine(T=self.T, loss="mine", method="concat")
        self.mine.optimize(self.X, y, iters=100, batch_size=self.X.shape[0])

    def forward(self, y):
        y = y.repeat(1, self.X.shape[1])
        return self.mine.mi(self.X, y)


class NeuralLeakageModel(nn.Module):
    def __init__(self, X, Y, keylen, leakAddr, assetDir) -> None:
        super().__init__()
        self.X = X
        self.device = "cpu"
        self.X = (X - X.mean()) / (X.std() + 1e-5)
        self.keylen = keylen
        self.Y = self.binary(Y).reshape(Y.shape[0], keylen)
        self.OriginalY = Y
        self.assetDir = assetDir
        self.HUnits = 50
        self.LeakageModels = []
        self.leakAddr = leakAddr
        log.debug(f"{X.shape[0]} samples")
        log.debug(f"{X.shape[1]} entries / samples")

    def train(self):
        self.MIScores = []
        heatmaps = []

        for idx, x in tqdm(enumerate(self.X.T)):
            if idx == 3:
                break
            x = x[:, None]
            x_train, x_val, y_train, y_val = train_test_split(
                x, self.Y, test_size=0.5, random_state=42
            )
            lm = nn.Sequential(
                nn.Linear(self.keylen, self.HUnits),
                nn.Dropout(0.5),
                nn.ReLU(),
                nn.Linear(self.HUnits, self.HUnits),
                nn.Dropout(0.5),
                nn.ReLU(),
                nn.Linear(self.HUnits, 1),
            ).to(self.device)
            optim = torch.optim.Adam(lm.parameters(), lr=1e-3)
            Y = []
            X_val = []
            Y_val = []
            icount = 0
            mest_val = MIEstimator(x_val)
            mest_train = MIEstimator(x_train)
            for e in range(1, 500):
                lpred = lm(y_train)
                mest_train.trainEstimator(lpred)
                loss = -mest_train.forward(lpred)
                optim.zero_grad()
                loss.backward()
                optim.step()
                if -loss > 1.0:
                    icount += 1
                    if icount > 30:
                        break
                if e % 10 == 0:
                    lm.eval()
                    with torch.no_grad():
                        lpred = lm(y_val)
                    mest_val.trainEstimator(lpred)
                    loss_val = -mest_val.forward(lpred)
                    Y_val.append(loss_val.cpu().detach().numpy())
                    X_val.append(e)
                    log.debug(f"val loss at epoch {e} is {loss_val:.8f}")
                    lm.train()
                Y.append(loss.cpu().detach().numpy())
            lm.eval()
            lpred = lm(self.Y)
            mest_total = MIEstimator(x)
            mest_total.trainEstimator(lpred)
            score = mest_total.forward(lpred).detach().cpu().numpy()
            # TODO add sklearn call for comp.
            log.info(f"MI for iter {idx} of {hex(self.leakAddr)}: {score}")
            self.MIScores.append(score)
            input = torch.ones((1, self.keylen)) - 0.5
            lm.eval()
            input.requires_grad = True
            pred = lm.forward(input)
            grad = torch.autograd.grad(pred, input)[0]
            keys = minmax_scale(torch.abs(grad)[0].detach().cpu().numpy(), (0, 1))
            heatmaps.append(keys[::-1, None].T)
            self.MIScore = np.mean(self.MIScores)
            fig, ax = plt.subplots()
            ax.plot(Y)
            ax.plot(X_val, Y_val)
            fig.savefig(f"loss{hex(self.leakAddr)}-{idx}.png")
        if self.MIScore > 0.00001:
            grid_kws = {"height_ratios": (0.9, 0.05), "hspace": 0.5}
            sns.set(font_scale=0.4)
            plt.tight_layout()
            f, (ax, cbar_ax) = plt.subplots(2, gridspec_kw=grid_kws, figsize=(10, 2))
            ax = sns.heatmap(
                np.stack(heatmaps, axis=0).reshape(-1, heatmaps[0].shape[1]),
                ax=ax,
                xticklabels=[
                    (self.keylen - i) if i % 2 else " " for i in range(self.keylen)
                ],  # MSB to LSB
                yticklabels=[
                    f"inv-{i}" if i % 2 else " " for i in range(self.X.shape[1])
                ],  # MSB to LSB
                cbar_ax=cbar_ax,
                cbar_kws={"orientation": "horizontal"},
                square=True,
                cmap="Blues",
                linewidths=0.25,
            )
            ax.xaxis.set_label_position("top")
            f.savefig(
                f"{self.assetDir}/saliency-map-{hex(self.leakAddr)}.png",
                dpi=200,
                bbox_inches="tight",
            )

    def __call__(self, Y):
        return 1
        return self.LeakageModel(self.binary(Y).to(self.device))

    def binary(self, Y):
        YL = np.zeros((Y.shape[0], self.keylen))
        for i, x in enumerate(Y):  # row
            binR = bin(x[0].item())[2:].zfill(self.keylen)[::-1]
            for j, bit in enumerate(binR):  # col
                YL[i][j] = int(bit)
        return (
            torch.tensor(YL, dtype=torch.float32).to(self.device, dtype=torch.float32)
            - 0.5
        )
