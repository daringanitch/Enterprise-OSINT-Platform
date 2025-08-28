#\!/bin/bash
echo "Updating CLAUDE.md..."
cp CLAUDE.md CLAUDE.md.bak
TEMP_FILE="CLAUDE_temp.md"
if grep -q "## Current Repository State" CLAUDE.md; then
    sed '/## Current Repository State/,$d' CLAUDE.md > "$TEMP_FILE"
else
    cp CLAUDE.md "$TEMP_FILE"
fi
echo "" >> "$TEMP_FILE"
echo "## Current Repository State" >> "$TEMP_FILE"
echo "" >> "$TEMP_FILE"
echo "**Last Updated**: $(date +"%Y-%m-%d %H:%M:%S")" >> "$TEMP_FILE"
echo "**Branch**: $(git branch --show-current)" >> "$TEMP_FILE"
echo "**Latest Commit**: $(git rev-parse --short HEAD)" >> "$TEMP_FILE"
echo "" >> "$TEMP_FILE"
echo "### Recent Commits" >> "$TEMP_FILE"
echo "" >> "$TEMP_FILE"
git log --pretty=format:"- %h: %s (%cr)" -10 >> "$TEMP_FILE"
echo "" >> "$TEMP_FILE"
mv "$TEMP_FILE" CLAUDE.md
echo "Done\! Review with: git diff CLAUDE.md"
EOF < /dev/null