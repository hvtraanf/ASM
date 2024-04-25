using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ASM.Data.Migrations
{
    /// <inheritdoc />
    public partial class updateFK : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UserId",
                table: "JobSeeker",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "UserId",
                table: "Employer",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_JobSeeker_UserId",
                table: "JobSeeker",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Employer_UserId",
                table: "Employer",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Employer_AspNetUsers_UserId",
                table: "Employer",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict); // Change 'Cascade' to 'Restrict'

            migrationBuilder.AddForeignKey(
                name: "FK_JobSeeker_AspNetUsers_UserId",
                table: "JobSeeker",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict); // Change 'Cascade' to 'Restrict'
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Employer_AspNetUsers_UserId",
                table: "Employer");

            migrationBuilder.DropForeignKey(
                name: "FK_JobSeeker_AspNetUsers_UserId",
                table: "JobSeeker");

            migrationBuilder.DropIndex(
                name: "IX_JobSeeker_UserId",
                table: "JobSeeker");

            migrationBuilder.DropIndex(
                name: "IX_Employer_UserId",
                table: "Employer");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "JobSeeker");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "Employer");
        }
    }
}
