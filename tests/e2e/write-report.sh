# Sourced by test-driver.sh — writes JUnit XML report.
# Expects: TEST_NAMES[], TEST_RESULTS[], PASS, FAIL, ELAPSED, REPORT_FILE

TOTAL=$((PASS + FAIL))
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo "<testsuites tests=\"$TOTAL\" failures=\"$FAIL\" time=\"$ELAPSED\">"
  echo "  <testsuite name=\"e2e-firewall\" tests=\"$TOTAL\" failures=\"$FAIL\" time=\"$ELAPSED\">"
  for i in "${!TEST_NAMES[@]}"; do
    local_name="${TEST_NAMES[$i]}"
    local_result="${TEST_RESULTS[$i]}"
    # XML-escape the name
    local_name="${local_name//&/&amp;}"
    local_name="${local_name//</&lt;}"
    local_name="${local_name//>/&gt;}"
    local_name="${local_name//\"/&quot;}"
    if [[ "$local_result" == "pass" ]]; then
      echo "    <testcase name=\"$local_name\" />"
    else
      echo "    <testcase name=\"$local_name\">"
      echo "      <failure message=\"$local_name\" />"
      echo "    </testcase>"
    fi
  done
  echo "  </testsuite>"
  echo "</testsuites>"
} > "$REPORT_FILE"

echo "Report written to $REPORT_FILE"
