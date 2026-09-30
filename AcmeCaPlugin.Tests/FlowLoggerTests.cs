using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class FlowLoggerTests
    {
        private static FlowLogger NewLogger(string name = "TestFlow") =>
            new FlowLogger(NullLogger.Instance, name);

        [Fact]
        public void Constructor_NullLogger_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new FlowLogger(null, "flow"));
        }

        [Fact]
        public void Constructor_NullFlowName_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new FlowLogger(NullLogger.Instance, null));
        }

        [Fact]
        public void Step_NoDetail_Succeeds_NoFailures()
        {
            using var flow = NewLogger();
            flow.Step("StepA");
            Assert.False(flow.HasFailures);
            Assert.Contains("StepA", flow.GetSummary());
        }

        [Fact]
        public void Step_WithDetail_IncludedInSummary()
        {
            using var flow = NewLogger();
            flow.Step("StepA", "some-detail");
            Assert.Contains("some-detail", flow.GetSummary());
        }

        [Fact]
        public void Step_Action_Success_RecordsOk()
        {
            using var flow = NewLogger();
            var ran = false;
            flow.Step("DoWork", () => { ran = true; });
            Assert.True(ran);
            Assert.False(flow.HasFailures);
        }

        [Fact]
        public void Step_Action_Throws_RecordsFailureAndRethrows()
        {
            using var flow = NewLogger();
            Assert.Throws<InvalidOperationException>(() =>
                flow.Step("DoWork", () => throw new InvalidOperationException("bad")));
            Assert.True(flow.HasFailures);
            Assert.Contains("bad", flow.GetSummary());
        }

        [Fact]
        public void StepFunc_Success_ReturnsValue()
        {
            using var flow = NewLogger();
            var result = flow.Step("Compute", () => 42, detail: "meaning of life");
            Assert.Equal(42, result);
            Assert.False(flow.HasFailures);
        }

        [Fact]
        public void StepFunc_Throws_RecordsFailureAndRethrows()
        {
            using var flow = NewLogger();
            Assert.Throws<ArgumentException>(() =>
                flow.Step<int>("Compute", () => throw new ArgumentException("nope")));
            Assert.True(flow.HasFailures);
        }

        [Fact]
        public async Task StepAsync_Void_Success()
        {
            using var flow = NewLogger();
            await flow.StepAsync("AsyncWork", async () => { await Task.Delay(1); });
            Assert.False(flow.HasFailures);
        }

        [Fact]
        public async Task StepAsync_Void_Throws_RecordsFailureAndRethrows()
        {
            using var flow = NewLogger();
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await flow.StepAsync("AsyncWork", async () =>
                {
                    await Task.Delay(1);
                    throw new InvalidOperationException("async-bad");
                }));
            Assert.True(flow.HasFailures);
        }

        [Fact]
        public async Task StepAsync_Generic_Success_ReturnsValue()
        {
            using var flow = NewLogger();
            var result = await flow.StepAsync("AsyncCompute", async () =>
            {
                await Task.Delay(1);
                return "value";
            }, detail: "d");
            Assert.Equal("value", result);
        }

        [Fact]
        public async Task StepAsync_Generic_Throws_RecordsFailureAndRethrows()
        {
            using var flow = NewLogger();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await flow.StepAsync<string>("AsyncCompute", async () =>
                {
                    await Task.Delay(1);
                    throw new ArgumentException("async-nope");
                }));
            Assert.True(flow.HasFailures);
        }

        [Fact]
        public void Fail_RecordsFailure()
        {
            using var flow = NewLogger();
            flow.Fail("SomeStep", "reason text");
            Assert.True(flow.HasFailures);
            Assert.Contains("reason text", flow.GetSummary());
        }

        [Fact]
        public void Skip_DoesNotRecordFailure()
        {
            using var flow = NewLogger();
            flow.Skip("SomeStep", "already done");
            Assert.False(flow.HasFailures);
            Assert.Contains("already done", flow.GetSummary());
            Assert.Contains("skipped", flow.GetSummary());
        }

        [Fact]
        public void Branch_EndBranch_IndentsAndUnindents()
        {
            using var flow = NewLogger();
            flow.Branch("Outer");
            flow.Step("Inner");
            flow.EndBranch();
            var summary = flow.GetSummary();
            Assert.Contains("Inner", summary);
        }

        [Fact]
        public void EndBranch_WithoutBranch_DoesNotThrow()
        {
            using var flow = NewLogger();
            flow.EndBranch(); // stack empty; should be a no-op
            Assert.False(flow.HasFailures);
        }

        [Fact]
        public void GetSummary_MixedStatuses_ReportsCounts()
        {
            using var flow = NewLogger();
            flow.Step("Ok1");
            flow.Fail("Fail1", "err");
            flow.Skip("Skip1", "why");

            var summary = flow.GetSummary();
            Assert.Contains("3 total, 1 ok, 1 failed, 1 skipped", summary);
            Assert.Contains("[FAILED]", summary);
        }

        [Fact]
        public void GetSummary_AllOk_ReportsOkOverallStatus()
        {
            using var flow = NewLogger();
            flow.Step("Ok1");
            Assert.Contains("[OK]", flow.GetSummary());
        }

        [Fact]
        public void Dispose_DoesNotThrow()
        {
            var flow = NewLogger();
            flow.Step("Ok1");
            flow.Dispose();
        }
    }
}
