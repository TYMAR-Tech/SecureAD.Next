namespace SecureAD.Evidence.Run;

/// <summary>
/// When a run happened, and whether the run itself said so.
/// </summary>
/// <remarks>
/// <para>
/// <b>The two are carried together because they are different claims.</b> A sealed run records the
/// moment it finished, and a run that ended badly records the moment it stopped; either is the
/// run's own statement. A run that was interrupted recorded nothing, and the only moment left is
/// when its directory was created - which is true on the machine that made it and changes the
/// moment somebody copies the bundle elsewhere. Presenting that as the run's moment would state a
/// fact nobody recorded.
/// </para>
/// <para>
/// <b>Nothing is read out of the run's name.</b> The name carries a timestamp as a convenience for
/// somebody reading a folder listing, and <see cref="RunLibrary.CreateRun"/> is explicit that
/// nothing reads meaning back out of it.
/// </para>
/// </remarks>
/// <param name="Utc">The moment, in UTC.</param>
/// <param name="Recorded">
/// True when the run recorded this moment itself. False when it is the run directory's creation
/// time, standing in because the run never got far enough to record one.
/// </param>
public sealed record RunMoment(DateTimeOffset Utc, bool Recorded);
