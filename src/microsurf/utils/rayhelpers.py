# BEGIN RAY UTILS PROGRESS BAR (taken from https://docs.ray.io/en/latest/ray-core/examples/progress_bar.html)
from asyncio import Event
from typing import Tuple

import ray
from ray.actor import ActorHandle
from tqdm.rich import tqdm


@ray.remote
class ProgressBarActor:
    def __init__(self) -> None:
        self.counter = 0
        self.delta = 0
        self.event = Event()

    def update(self, num_items_completed: int) -> None:
        self.counter += num_items_completed
        self.delta += num_items_completed
        self.event.set()

    async def wait_for_update(self) -> Tuple[int, int]:
        await self.event.wait()
        self.event.clear()
        saved_delta = self.delta
        self.delta = 0
        return saved_delta, self.counter

    def get_counter(self) -> int:
        return self.counter


class ProgressBar:
    def __init__(self, total: int, description: str = ""):
        self.progress_actor = ProgressBarActor.remote()  # type: ignore
        self.total = total
        self.description = description

    @property
    def actor(self) -> ActorHandle:
        return self.progress_actor

    def print_until_done(self) -> None:
        pbar = tqdm(desc=self.description, total=self.total)
        while True:
            delta, counter = ray.get(self.actor.wait_for_update.remote())
            pbar.update(delta)
            if counter >= self.total:
                pbar.close()
                return

### END RAY PROGRESSBAR SNIPPET
