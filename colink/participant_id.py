import colink as CL
from typing import List


def get_participant_id(self, participants: List[CL.Participant]) -> int:
    for i, participant in enumerate(participants):
        if participant.user_id == self.get_user_id():
            return i
    return None
