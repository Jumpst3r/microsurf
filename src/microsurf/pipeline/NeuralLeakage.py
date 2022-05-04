import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import torch
import torch.nn as nn
import torch.nn.functional as F
from mine.models.mine import Mine
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import minmax_scale

from microsurf.utils.logger import getLogger

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
    def __init__(self, X, Y, leakAddr, keylen, assetDir, threshold) -> None:
        super().__init__()
        self.X = X
        self.threshold = threshold
        if len(self.X) <= 1:
            log.debug(f"sample count too low for {hex(leakAddr)}, returning MI = 0.0")
            self.abort = True
            self.MIScore = 0
        else:
            self.abort = False
            self.X = (X - X.mean(axis=0)) / (X.std(axis=0) + 1e-5)
        self.keylen = keylen
        self.Y = self.binary(Y).reshape(Y.shape[0], self.keylen)
        self.OriginalY = Y
        self.assetDir = assetDir
        self.HUnits = 50
        self.LeakageModels = []
        self.leakAddr = leakAddr

    def train(self):
        if self.abort:
            return
        self.MIScores = []
        heatmaps = []

        for idx, x in enumerate(self.X.T):
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
            )
            optim = torch.optim.Adam(lm.parameters(), lr=1e-3)
            Y = []
            X_val = []
            Y_val = []
            mest_val = MIEstimator(x_val)
            mest_train = MIEstimator(x_train)
            for e in range(1, 200):
                lpred = lm(y_train)
                mest_train.trainEstimator(lpred)
                loss = -mest_train.forward(lpred)
                optim.zero_grad()
                loss.backward()
                optim.step()
                if e % 10 == 0:
                    lm.eval()
                    with torch.no_grad():
                        lpred = lm(y_val)
                    mest_val.trainEstimator(lpred)
                    loss_val = -mest_val.forward(lpred)
                    Y_val.append(loss_val.detach().numpy())
                    X_val.append(e)
                    log.debug(
                        f"pc-{self.leakAddr} idx-{idx}/{len(self.X.T)}, e-{e}/200"
                    )
                    if len(Y_val) > 10:
                        new_val_mean = np.mean(Y_val[-5:])
                        old_val_mean = np.mean(Y_val[-10:-5])
                        eps = new_val_mean - old_val_mean
                        if eps > 0:
                            break
                    lm.train()
                Y.append(loss.detach().numpy())
            lm.eval()
            lpred = lm(self.Y)
            mest_total = MIEstimator(x)
            mest_total.trainEstimator(lpred)
            score = mest_total.forward(lpred).detach().numpy()
            # TODO add sklearn call for comp.
            self.MIScores.append(score)
            input = torch.ones((1, self.keylen)) - 0.5
            lm.eval()
            input.requires_grad = True
            pred = lm.forward(input)
            grad = torch.autograd.grad(pred, input)[0]
            keys = minmax_scale(torch.abs(grad)[0].detach().numpy(), (0, 1))
            heatmaps.append(keys[::-1, None].T)
        self.MIScore = abs(max(self.MIScores))
        if self.MIScore >= self.threshold:
            sns.set(font_scale=0.3)
            plt.tight_layout()
            try:
                dependencies = np.stack(heatmaps, axis=0).reshape(
                    -1, heatmaps[0].shape[1]
                )
            except Exception:
                return
            f, ax = plt.subplots(figsize=(8, 1.2 * len(heatmaps)))
            self.MIScores = np.array(self.MIScores[: len(heatmaps)])
            # add a column to the far right to include the MI score in the heatmap
            dependencies = np.c_[dependencies, self.MIScores]
            dependencies[dependencies[:, -1] < self.threshold] = 0
            deps = dependencies.copy()
            mi = dependencies.copy()
            deps.T[-1] = np.nan
            mi.T[:-1] = np.nan
            # plt.figure(figsize=(15, 2))
            ax = sns.heatmap(
                deps,
                ax=ax,
                vmin=0,
                vmax=1,
                cbar_kws={
                    "orientation": "horizontal",
                    "label": "Estimated key bit dependency",
                    "shrink": 0.5,
                },
                cmap="Blues",
                square=True,
            )
            sns.heatmap(
                mi,
                cmap="Reds",
                ax=ax,
                vmin=0,
                vmax=1,
                cbar_kws={
                    "label": "Estimated MI score per call",
                    "location": "top",
                    "shrink": 0.5,
                },
                xticklabels=[
                    (self.keylen - i) if i % 2 == 0 else " " for i in range(self.keylen)
                ]
                + ["MI"],
                yticklabels=[
                    f"inv-{i}" if i % 2 else " " for i in range(self.MIScores.shape[0])
                ],  # MSB to LSB
                linewidths=0.5,
                square=True,
            )
            ax.xaxis.set_label_position("top")
            f.savefig(
                f"{self.assetDir}/saliency-map-{hex(self.leakAddr)}.png",
                dpi=300,
                bbox_inches="tight",
            )

    def binary(self, Y):
        YL = np.zeros((Y.shape[0], self.keylen))
        for i, x in enumerate(Y):  # row
            binR = bin(x)[2:].zfill(self.keylen)[::-1]
            for j, bit in enumerate(binR):  # col
                YL[i][j] = int(bit)
        return torch.tensor(YL, dtype=torch.float32) - 0.5
