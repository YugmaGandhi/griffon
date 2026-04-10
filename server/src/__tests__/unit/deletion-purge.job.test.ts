import { startDeletionPurgeJob } from '../../jobs/deletion-purge.job';
import { deletionService } from '../../services/deletion.service';

jest.mock('../../services/deletion.service', () => ({
  deletionService: { purgeExpired: jest.fn() },
}));

const mockPurgeExpired = deletionService.purgeExpired as jest.Mock;

describe('startDeletionPurgeJob()', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return an interval handle', () => {
    const handle = startDeletionPurgeJob();
    expect(handle).toBeDefined();
    clearInterval(handle);
  });

  it('should call purgeExpired after 1 hour', async () => {
    mockPurgeExpired.mockResolvedValue(0);

    const handle = startDeletionPurgeJob();

    jest.advanceTimersByTime(60 * 60 * 1000);
    // Flush the async callback in the interval
    await Promise.resolve();

    expect(mockPurgeExpired).toHaveBeenCalledTimes(1);

    clearInterval(handle);
  });

  it('should not throw if purgeExpired rejects', async () => {
    mockPurgeExpired.mockRejectedValue(new Error('DB error'));

    const handle = startDeletionPurgeJob();

    jest.advanceTimersByTime(60 * 60 * 1000);
    await Promise.resolve();

    // Job should swallow the error — no unhandled rejection
    expect(mockPurgeExpired).toHaveBeenCalled();

    clearInterval(handle);
  });
});
