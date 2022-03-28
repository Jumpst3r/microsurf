import logging
from matplotlib.pyplot import yticks
from mine.models.mine import Mine
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import minmax_scale
import torch
from microsurf.utils.logger import LOGGING_LEVEL, getLogger
import seaborn as sns

log = getLogger()


class MIEstimator(nn.Module):
    def __init__(self, X) -> None:
        super().__init__()
        self.X = torch.tensor(minmax_scale(np.array(X, dtype=np.float32), (-1, 1)))
        self.T = nn.Sequential(
            nn.Linear(self.X.shape[1] * 2, 100),
            nn.ReLU(),
            nn.Linear(100, 100),
            nn.ReLU(),
            nn.Linear(100, 1),
        )
        self.mine = Mine(T=self.T, loss="mine", method="concat")

    def trainEstimator(self, y):
        y = torch.tensor(y).expand(y.shape[0], self.X.shape[1])
        self.mine.optimize(self.X, y, iters=100, batch_size=self.X.shape[0])

    def forward(self, y):
        y = y.repeat(1, self.X.shape[1])
        return self.mine.mi(self.X, y)


class NeuralLeakageModel(nn.Module):
    def __init__(self, X, Y, keylen, leakAddr, assetDir) -> None:
        super().__init__()
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.X = minmax_scale(np.array(X, dtype=np.float64), (-1, 1))
        self.keylen = keylen
        self.Y = self.binary(Y).reshape(Y.shape[0], keylen)
        self.OriginalY = Y
        self.assetDir = assetDir
        self.HUnits = 300
        self.LeakageModel = nn.Sequential(
            nn.Linear(keylen, self.HUnits),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(self.HUnits, self.HUnits),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(self.HUnits, 1),
        ).to(self.device)
        self.leakAddr = leakAddr

    def train(self):
        optim = torch.optim.Adam(self.LeakageModel.parameters(), lr=1e-3)
        mest = MIEstimator(self.X)
        X = []
        Y = []
        icount = 0
        for e in range(200):
            lpred = self.LeakageModel(self.Y)
            mest.trainEstimator(lpred)
            loss = -mest.forward(lpred)
            optim.zero_grad()
            loss.backward()
            # stop learning if MI doesn't increase => FP
            if e >= 40 and -loss < 0.001:
                break
            optim.step()
            # good enough, stop
            if -loss > 1.0:
                icount += 1
                if icount > 10:
                    break
            if e % 10 == 0:
                log.debug(f"loss at epoch {e} is {loss:.8f}")
            X.append(e)
            Y.append(loss.cpu().detach().numpy())
        self.LeakageModel.eval()
        lpred = self.LeakageModel(self.Y)
        mest.trainEstimator(lpred)
        self.MIScore = mest.forward(lpred)

        if self.MIScore > 0.3:
            import matplotlib.pyplot as plt
            input = self.binary(torch.tensor(2 ** (self.keylen) - 1)).reshape(
                1, self.keylen
            )
            self.LeakageModel.eval()
            input.requires_grad = True
            pred = self.LeakageModel(input)
            pred.backward()
            keys = minmax_scale(torch.abs(input.grad)[0].detach().cpu().numpy(), (0, 1))
            grid_kws = {"height_ratios": (.9, .05), "hspace": .0001}
            sns.set(font_scale=0.4)
            plt.tight_layout()
            f, (ax, cbar_ax) = plt.subplots(2, gridspec_kw=grid_kws, figsize=(7,2))
            ax = sns.heatmap(
                keys[:, None].T,
                ax=ax,
                cbar_ax=cbar_ax,
                cbar_kws={"orientation": "horizontal"},
                square=True,
                cmap='Blues',
                yticklabels=False
            )
            f.savefig(f"{self.assetDir}/saliency-map-{hex(self.leakAddr)}.png", dpi=200, bbox_inches='tight')

    def __call__(self, Y):
        return self.LeakageModel(self.binary(Y).to(self.device))

    def binary(self, Y):
        Y = torch.tensor(Y, dtype=torch.int64)
        mask = 2 ** torch.arange(self.keylen)
        return (
            Y.unsqueeze(-1)
            .bitwise_and(mask)
            .ne(0)
            .byte()
            .to(self.device, dtype=torch.float32)
        )
