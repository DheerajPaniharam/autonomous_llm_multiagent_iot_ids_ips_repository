from backend.agents.queues import get_queues


def test_risk_and_orchestrator_queues_are_separate_types():
    queues = get_queues()

    assert queues.risk_queue is not queues.orchestrator_queue
    assert queues.risk_queue.__class__.__name__ == 'Queue'
    assert queues.orchestrator_queue.__class__.__name__ == 'PriorityQueue'
