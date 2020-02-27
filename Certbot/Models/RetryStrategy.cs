using System;

namespace Certbot.Models
{
    public static class RetryStrategy
    {
        public static bool RetriableException(Exception exception)
        {
            return exception.InnerException is RetriableActivityException;
        }
    }
}
